import torch
from torch.nn import functional as F
from sklearn.metrics.pairwise import cosine_similarity
import re
from fuzzywuzzy import process
from assistant.data_loader import normalize_results
from assistant.embeddings import get_embedding_model
from assistant.llm import get_device, get_tokenizer
import faiss
from .models import ChatSession, Message
import re
from collections import Counter, defaultdict

embedding_model = get_embedding_model()
device = get_device()
tokenizer = get_tokenizer()

def understand_query_intent(query):
  categories = {

    "attack_pattern":
        """
        Questions asking about attack techniques, attack patterns,
        TTPs (tactics, techniques and procedures), methods,
        behaviors, sub-techniques, actions performed by malware,
        actions performed by threat actors, or how an attack is carried out.
        
        Examples:
        Which techniques does this malware use?
        Which attack patterns are associated with this malware?
        What techniques does this threat group use?
        What methods does this malware employ?
        What behaviors are associated with this attack?
        Which ATT&CK techniques are linked to this malware?
        What TTPs are used by this intrusion set?
        Which attack techniques does WireLurker use?
        Which techniques does Turla use?
        How is this attack carried out?
        """
      ,
      
    "mitigation": 
        """  
        Questions asking how to prevent, defend against, mitigate,
        detect, monitor, reduce the impact of, secure systems against,
        identify, block, stop, or protect against a cybersecurity attack.

        Examples:
        How can this attack be prevented?
        How do I mitigate this technique?
        How can organizations defend against this?
        What security controls stop this attack?
        How can I detect this technique?
        What monitoring should be used?
        How can defenders identify this activity?
        What protections should be implemented?
        What are the recommended mitigations?
        """
      ,

    "malware": 
        """
        Questions asking about malware, malicious software, viruses,
        trojans, worms, ransomware, spyware, backdoors, implants,
        malware families, malware variants, malicious tools, malware
        campaigns, or software associated with a technique.

        Examples:
        Which malware uses this technique?
        What malware is associated with this attack?
        Which virus uses this attack?
        Which trojan uses this technique?
        Which ransomware uses this attack?
        What malware families are linked to this technique?
        Has any malware been observed using this attack?
        Which malicious software uses this persistence mechanism?
        What malware campaigns leverage this technique?
        """
      ,

    "intrusion_set": 
        """
        Questions asking about threat actors, adversaries, attacker groups,
        hacking groups, intrusion sets, advanced persistent threats (APT),
        cybercriminal organizations, nation-state groups, threat groups,
        attacker campaigns, or who is known to use a technique.

        Examples:
        Which threat group uses this technique?
        Which attack group uses this attack?
        Who uses this technique?
        Which APT group uses this?
        What threat actors are associated with this attack?
        Which adversaries leverage this technique?
        Which hacking groups use this persistence mechanism?
        What intrusion sets are linked to this attack?
        Who has been observed using this technique?
        Which nation-state actors use this attack?
        """
      ,
  }


  example = []

  name_category = []
  description_category = []

  for key, values in categories.items():
    name_category.append(key)
    description_category.append(values)    



  category_embeddings = embedding_model.encode(
      description_category,
      convert_to_tensor = True,
      device = device
  )

  query_embedding = embedding_model.encode(
      [query],
      convert_to_tensor = True,
      device = device
  )


  similarity = F.cosine_similarity(
      query_embedding,
      category_embeddings
  )

    
  scores, indices = torch.topk(similarity, k = 3)

  key_word_found = False
  
  intent = []

  seen = set()

  q = query.lower() 

  if any(x in q for x in [
      "malware",
      "virus",
      "trojan",
      "ransomware",
      "backdoor"
  ]):
    intent.append("malware")
    key_word_found = True



  if any(x in q for x in [
      "apt",
      "threat group",
      "attack group",
      "intrusion set",
      "adversary",
      "actor"
  ]):
      intent.append("intrusion_set")
      key_word_found = True

  if any(x in q for x in [
      "mitigate",
      "prevent",
      "defend",
      "protect",
      "detect"
  ]):
    intent.append("mitigation")
    key_word_found = True

  if not key_word_found:
    for idx, score in zip(indices, scores):

      category = name_category[idx.item()]

      if category in seen:
        continue

      seen.add(category)
      intent.append(category)

  return intent



def exact_match(query, entity_chunk):
  q = query.lower()

  words = set(re.findall(r"\w+", q))


  for entity in entity_chunk:
      
      entity_name = entity["name"].lower()

      if entity_name in words:
          print("EXACT:", entity["name"])
          return entity 



def generate_n_grams(query, max_n = 3):
    words = re.findall(r"\w+", query.lower())

    ngrams = []

    for n in range(1, max_n + 1):
        for i in range(len(words) - n + 1):
            ngrams.append(" ".join(words[i:i+n]))


    return ngrams
            



def fuzzy_match(query, entity_chunk, ngrams):
    query = query.lower()


    entity_names = []

    for entity in entity_chunk:
        entity_names.append(entity["name"])


    match = process.extractOne(
        query,
        entity_names
    )

    print(match)



    ngrams = generate_n_grams(query)

    best_match = None
    best_score = 0

    for grams in ngrams:
        match = process.extractOne(
            grams,
            entity_names
        )
        if match[1] < 88:
            return None

        if match and match[1] > best_score:
            best_match = match
            best_score = match[1]
            print("BEST MATCH N GRAMS: ", best_match, "BEST SCORE: ", best_score)

    matched_name = best_match[0]


    entity = next(
        x for x in entity_chunk
        if x["name"] == matched_name
        
    )
    
    return entity






def relationship_queries(query, intent):
    query_types =[
        # Overview Targets
        ("What is an overview of this entity?", "overview"),
        ("Tell me about this threat actor.", "overview"),
        ("Explain the background of this software.", "overview"),
        ("Give me information and summary details.", "overview"),
        # Relationship Targets
        ("What entities are linked or connected to this?", "relationship"),
        ("What are the associations of this profile?", "relationship"),
        ("Show me the map of connected items.", "relationship")
    ]
    
    relationship_keywords = [
        "which",
        "uses",
        "use",
        "techniques",
        "technique",
        "malware",
        "mitigation",
        "mitigated",
        "group",
        "groups",
        "associated",
        "related",
        "linked",
        "connect",
        "connected",
        "employs",
        "utilizes"
    ]
    
    q = query.lower().strip()
    clean_query = re.findall(r"\w+", q)
    

    if any(x in relationship_keywords for x in clean_query):
        best_query_type = "relationship"
        return best_query_type

    
    phrases = [item[0] for item in query_types]
    intents = [item[1] for item in query_types]

    query_embeddings = embedding_model.encode(
        [query],
        convert_to_tensor = True,
        device = device
    )

    query_types_embeddings = embedding_model.encode(
        phrases,
        convert_to_tensor = True,
        device = device
    )

    similarity = cosine_similarity(
        query_embeddings.cpu().numpy(),
        query_types_embeddings.cpu().numpy()
    )[0]


    best_match_index = similarity.argmax().item()
    best_score = similarity[best_match_index]
    best_query_type = intents[best_match_index]

    print(f"Query: '{query}' -> Closest Anchor: '{intents[best_match_index]}' (Score: {best_score:.3f})")

    print(best_query_type)

    return best_query_type



# FOR EXACT AND FUZZY MATCHING
def build_context(entity, intent, best_query_type):
    all_context = []

    all_context.append(entity["text"])

    if best_query_type == "overview":
        context = "\n\n".join(all_context)
        return context
    
    categories = {
      x
      for x in intent 
    }
    
    attack_count = 0
    malware_count = 0
    intrusion_count = 0
    mitigation_count = 0

    if "malware" in categories:
        for m in entity.get("malware", []):
          if malware_count >=6:
              break
          all_context.append(
              f"""
              Malware Name: 
              {m["name"]}
              
              Malware Description: 
              {m["description"]}
              """
          )
          malware_count += 1
    
    if "intrusion_set" in categories:
        for intrusion in entity.get("intrusion_set", []):
          if intrusion_count >= 6:
              break
          all_context.append(
              f"""
              Intrusion Set Name: 
              {intrusion["name"]}
              
              Intrusion Set Description: 
              {intrusion["description"]}
              """
          )
          intrusion_count += 1
    
    if "mitigation" in categories:
        for miti in entity.get("mitigation", []):
          if mitigation_count >=6:
              break
          all_context.append(
              f"""
              Mitigation Name: 
              {miti["name"]}
              
              Mitigation Description: 
              {miti["description"]}
              """
          )
          mitigation_count += 1
    
    if "attack_pattern" in categories:
        for attack in entity.get("attack_pattern", []):
          if attack_count >= 6:
              break
          all_context.append(
              f"""
              Attack Pattern Name: 
              {attack["name"]}
              
              Attack Pattern Description: 
              {attack["description"]}
              """
          )
          attack_count += 1
    
    context = "\n\n".join(all_context)
    
    return context


def resolve_entity(query, entity_chunk, intent, best_query_type, ngrams):     
    entity = exact_match(query, entity_chunk)

    print("EXACT MATCH ENTITY: ", entity)

    if entity:
        context = build_context(entity=entity, intent=intent, best_query_type=best_query_type)
        return context

    entity = fuzzy_match(query, entity_chunk, ngrams)

    print("FUZZY MATCH ENTITY: ", entity)

    if entity:
        context = build_context(entity=entity, intent=intent, best_query_type=best_query_type)
        return context
    return None







# FOR FAISS RETRIEVAL
def get_context(query, entity_chunk):  
  query_embeddings = embedding_model.encode(
      [query],
      convert_to_tensor = True,
      device = device
  )

  query_embeddings_np = query_embeddings.cpu().numpy().astype("float32")

  faiss.normalize_L2(query_embeddings_np)

  retrieved_chunks = []
  

  index = faiss.read_index("indices/doc_mitre-all")


    
  distance, indices = index.search(query_embeddings_np, k=5)


  for i in indices[0]:
    retrieved_chunks.append(
        entity_chunk[int(i)]
    )


  return retrieved_chunks





def final_context(retrieved_chunks, intent, best_query_type):
  all_context = []
  
  if best_query_type == "overview":
    for entity in retrieved_chunks[:5]:
        all_context.append(entity["text"])

    context = "\n\n".join(all_context)
    return context


  categories = {
      x
      for x in intent 
  }

  attack_count = 0
  malware_count = 0
  intrusion_count = 0
  mitigation_count = 0

    
  if "malware" in categories:
    for m in entity.get("malware", []):
      if malware_count >=6:
          break
      all_context.append(
          f"""
          Malware Name: 
          {m["name"]}
          
          Malware Description: 
          {m["description"]}
          """
      )
      malware_count += 1
  
  if "intrusion_set" in categories:
    for intrusion in entity.get("intrusion_set", []):
      if intrusion_count >= 6:
          break
      all_context.append(
          f"""
          Intrusion Set Name: 
          {intrusion["name"]}
          
          Intrusion Set Description: 
          {intrusion["description"]}
          """
      )
      intrusion_count += 1
  
  if "mitigation" in categories:
    for miti in entity.get("mitigation", []):
      if mitigation_count >=6:
          break
      all_context.append(
          f"""
          Mitigation Name: 
          {miti["name"]}
          
          Mitigation Description: 
          {miti["description"]}
          """
      )
      mitigation_count += 1
  
  if "attack_pattern" in categories:
    for attack in entity.get("attack_pattern", []):
      if attack_count >= 6:
          break
      all_context.append(
          f"""
          Attack Pattern Name: 
          {attack["name"]}
          
          Attack Pattern Description: 
          {attack["description"]}
          """
      )
      attack_count += 1
  
  context = "\n\n".join(all_context)

  return context



def retrieve_previous_messages(session):
   messages = session.messages.all()

   previous_messages = []

   for message in messages:
      previous_messages.append(
         {
            "role": message.role,
            "content": message.content
         }
      )
   return previous_messages 


def processing_attributes(url_analysis, url_haus_result, url_to_search):
    url_haus_detected = url_haus_result.get("detected")

    TIER_1_AV = {
        "Kaspersky",
        "BitDefender",
        "ESET-NOD32",
        "Microsoft",
        "Sophos",
        "TrendMicro",
        "Avast",
        "AVG",
        "Malwarebytes",
        "CrowdStrike"
    }

    TIER_2_AV = {
        "Fortinet",
        "GData",
        "FSecure",
        "McAfee",
        "Tencent",
        "Cyren"
    }

    REPUTATION_PROVIDERS = {
        "Google Safebrowsing",
        "OpenPhish",
        "PhishTank"
    }


    """
    Types of vrius total results contain

    result = "Phishing"
    result = "Trojan"
    result = "Malware"
    result = "Suspicious"

    """

    AV_HIGH_CONFIDENCE = {
        "ransomware",
        "trojan",
        "infostealer",
        "banker",
        "botnet",
        "rootkit",
        "wiper",
        "malware"
    }

    AV_MEDIUM_CONFIDENCE = {
        "adware",
        "cryptominer",
        "downloader",
        "worm",
        "suspicious"
    }

    REPUTATION_HIGH_CONFIDENCE = {
        "phishing"
    }

    REPUTATION_MEDIUM_CONFIDENCE = {
        "suspicious",
        "fraud",
        "scam"
    }



    analysis = {
        "verdict": None,
        "confidence": None,

        "dominant_threat_av": None,
        "dominant_threat_reputation": None,

        "dominant_threats": None,

        "evidence": [],
        "evidence_summary": None,

        "threat_distribution": {},

        "av_very_harmful": 0,
        "av_medium_harmful": 0,
        "av_clean": 0,

        "reputation_very_harmful": 0,
        "reputation_medium_harmful": 0,
        "reputation_clean": 0,

        "clean_engines": {
            "tier_1_av": [],
            "tier_2_av": [],
            "reputation": []
        },


        "conflicting_assesment": False,

        "urlhaus_detected": False,

        "supporting_engines": None,

        "key_findings": []
    }



    if url_haus_detected == True:
        analysis["urlhaus_detected"] = True

    engine_name = url_analysis.keys()

    harmless_count = 0
    malicious_count = 0
    suspicious_count = 0
    undetected_count = 0


    engine_results = []


    for engine in engine_name:
        engine_data = url_analysis.get(engine)

        category = engine_data.get("category")
        engine_name = engine_data.get("engine_name")
        scan_result = engine_data.get("result")


        if category == "harmless":
            harmless_count += 1
        if category == "malicious":
            malicious_count += 1
        if category == "suspicious":
            suspicious_count += 1
        if category == "undetected":
            undetected_count += 1


        engine_results.append({
            "name": engine_name,
            "category": category,
            "result": scan_result
        })

    tier_1_av_high = 0
    tier_1_av_medium = 0
    tier_2_av_high = 0
    tier_2_av_medium = 0
    reputation_high = 0
    reputation_medium = 0


    tier_1_av_clean = 0
    tier_2_av_clean = 0
    reputation_clean = 0
    tier_1_av_clean_engines = []
    tier_2_av_clean_engines = []
    reputation_clean_engines = []

    all_threat_counter = Counter()

    tier_1_av_threat_counter = Counter()

    tier_2_av_threat_counter = Counter()

    reputation_threat_counter = Counter()



    tier_1_av_support = defaultdict(list)
    tier_2_av_support = defaultdict(list)
    reputation_support = defaultdict(list)



    tier_1_av_identified_threats = []
    tier_2_av_identified_threats = []
    reputation_identified_threats = []

    tier_1_av_most_dominant = None
    tier_2_av_most_dominant = None
    reputation_most_dominant = None

    for engine in engine_results:
        name = engine["name"]
        result = engine["result"]
        category = engine["category"]

        print(
            f"Engine: {name}, Category: {category}, Result: {result}"
        )

        if category == "harmless":
            if name in TIER_1_AV:
                tier_1_av_clean += 1
                tier_1_av_clean_engines.append(name)
            elif name in TIER_2_AV:
                tier_2_av_clean += 1
                tier_2_av_clean_engines.append(name)
            if name in REPUTATION_PROVIDERS:
                reputation_clean += 1
                reputation_clean_engines.append(name)
            continue


        normalized_result = normalize_results(result)


        if not normalized_result:
           continue

        all_threat_counter[normalized_result] += 1

        if name in TIER_1_AV:
            tier_1_av_threat_counter[normalized_result] += 1
            tier_1_av_support[normalized_result].append(name)

        elif name in TIER_2_AV:
            tier_2_av_threat_counter[normalized_result] += 1
            tier_2_av_support[normalized_result].append(name)

        if name in REPUTATION_PROVIDERS:
            reputation_threat_counter[normalized_result] += 1
            reputation_support[normalized_result].append(name)



        if name in TIER_1_AV and normalized_result in AV_HIGH_CONFIDENCE:
            tier_1_av_high += 1

        if name in TIER_1_AV and normalized_result in AV_MEDIUM_CONFIDENCE:
            tier_1_av_medium += 1

        if name in TIER_2_AV and normalized_result in AV_HIGH_CONFIDENCE:
            tier_2_av_high += 1

        if name in TIER_2_AV and normalized_result in AV_MEDIUM_CONFIDENCE:
            tier_2_av_medium += 1

        if name in REPUTATION_PROVIDERS and normalized_result in REPUTATION_HIGH_CONFIDENCE:
            reputation_high += 1

        if name in REPUTATION_PROVIDERS and normalized_result in REPUTATION_MEDIUM_CONFIDENCE:
            reputation_medium += 1

    if tier_1_av_threat_counter:
        tier_1_av_identified_threats = tier_1_av_threat_counter.most_common()
        tier_1_av_most_dominant = tier_1_av_threat_counter.most_common(1)[0][0]

    if tier_2_av_threat_counter:
        tier_2_av_identified_threats = tier_2_av_threat_counter.most_common()
        tier_2_av_most_dominant = tier_2_av_threat_counter.most_common(1)[0][0]

    if reputation_threat_counter:
        reputation_identified_threats = reputation_threat_counter.most_common()
        reputation_most_dominant = reputation_threat_counter.most_common(1)[0][0]

    trusted_av_very_harmful = tier_1_av_high + tier_2_av_high
    analysis["trusted_av_very_harmful"] = trusted_av_very_harmful

    trusted_av_medium_harmful = tier_1_av_medium + tier_2_av_medium
    analysis["trusted_av_medium_harmful"] = trusted_av_medium_harmful


    trusted_reputation_very_harmful = reputation_high
    analysis["trusted_reputation_very_harmful"] = trusted_reputation_very_harmful

    trusted_reputation_medium_harmful = reputation_medium
    analysis["trusted_reputation_medium_harmful"] = trusted_reputation_medium_harmful

    trusted_clean_av = tier_1_av_clean + tier_2_av_clean

    trusted_reputation_clean = reputation_clean


    analysis["clean_engines"]["tier_1_av"] = tier_1_av_clean_engines
    analysis["clean_engines"]["tier_2_av"] = tier_2_av_clean_engines
    analysis["clean_engines"]["reputation"] = reputation_clean_engines

    analysis["av_very_harmful"] = trusted_av_very_harmful
    analysis["av_medium_harmful"] = trusted_av_medium_harmful
    analysis["reputation_very_harmful"] = trusted_reputation_very_harmful
    analysis["reputation_medium_harmful"] = trusted_reputation_medium_harmful

    analysis["av_clean"] = trusted_clean_av
    analysis["reputation_clean"] = trusted_reputation_clean


    analysis["threat_distribution"] = {
        "tier_1_av": tier_1_av_identified_threats,
        "tier_2_av": tier_2_av_identified_threats,
        "reputation": reputation_identified_threats
    }



    if tier_1_av_most_dominant:
        analysis["dominant_threat_av"] = tier_1_av_most_dominant

    elif tier_2_av_most_dominant:
        analysis["dominant_threat_av"] = tier_2_av_most_dominant

    if reputation_most_dominant:
        analysis["dominant_threat_reputation"] = reputation_most_dominant

    
    analysis["dominant_threats"] = {
        "tier_1_av": tier_1_av_most_dominant,
        "tier_2_av": tier_2_av_most_dominant,
        "reputation": reputation_most_dominant
    }


    analysis["supporting_engines"] = {
        "tier_1_av": dict(tier_1_av_support),
        "tier_2_av": dict(tier_2_av_support),
        "reputation": dict(reputation_support)
    }


    total_harmful = (
        tier_1_av_high + tier_1_av_medium + tier_2_av_high + tier_2_av_medium + reputation_high + reputation_medium
    )

    total_clean = (
        tier_1_av_clean + tier_2_av_clean + reputation_clean
    )

    if total_harmful > 0 and total_clean > 0:
        analysis["conflicting_assesment"] = True
    

    if (
        total_harmful >= 1
        and total_clean >= 2
    ):
        analysis["conflicting_assesment"] = True


    if analysis["urlhaus_detected"] == True:
        analysis["verdict"] = "HIGH RISK"


    elif tier_1_av_high >= 2:
        analysis["verdict"] = "HIGH RISK"

    elif tier_2_av_high >= 2:
        analysis["verdict"] = "HIGH RISK"

    elif tier_1_av_high >= 1 and reputation_high >= 1:
        analysis["verdict"] = "HIGH RISK"

    elif reputation_high >= 2:
        analysis["verdict"] = "HIGH RISK"




    elif tier_1_av_high >= 1:
        analysis["verdict"] = "CAUTION"



    elif tier_1_av_medium >= 1:
        analysis["verdict"] = "CAUTION"

    elif tier_2_av_medium >= 1:
        analysis["verdict"] = "CAUTION"


    elif reputation_high >= 1:
        analysis["verdict"] = "CAUTION"

    elif reputation_medium >= 1:
        analysis["verdict"] = "CAUTION"


    if analysis["verdict"] is None:

        if analysis["conflicting_assesment"]:
            analysis["verdict"] = "CAUTION"

        elif analysis["av_clean"] >= 2:
            analysis["verdict"] = "SAFE"

        elif analysis["reputation_clean"] >= 2:
            analysis["verdict"] = "SAFE"

        else:
            analysis["verdict"] = "UNKNOWN"

    confidence_score = 0

    if analysis["urlhaus_detected"] == True:
        confidence_score += 5


    confidence_score += tier_1_av_high * 3

    confidence_score += tier_2_av_high * 2

    confidence_score += tier_1_av_medium * 2

    confidence_score += tier_2_av_medium * 1


    confidence_score += reputation_high * 3

    confidence_score += reputation_medium * 1



    confidence_score += min(
        analysis["av_clean"],
        3
    )

    confidence_score += min(
        analysis["reputation_clean"],
        2
    )


    if analysis["conflicting_assesment"]:
        confidence_score -= 2


    if confidence_score >= 6:
        analysis["confidence"] = "HIGH"

    elif confidence_score >= 3:
        analysis["confidence"] = "MEDIUM"

    else:
        analysis["confidence"] = "LOW"




    if analysis["urlhaus_detected"]:
        analysis["key_findings"].append(
            "URLhaus lists this URL as malware distribution infrastructure."
        )
    
        analysis["evidence"].append({
            "type": "urlhaus",
            "url": url_to_search,
            "status": url_haus_result["url_status"],
            "threat": url_haus_result["threat"],
            "tag": url_haus_result["indicators"],
        })
    
    
    if tier_1_av_most_dominant:
        analysis["key_findings"].append(
            f"Trusted antivirus vendors primarily identified {tier_1_av_most_dominant} activity."
        )

    elif tier_2_av_most_dominant:
        analysis["key_findings"].append(
            f"Multiple antivirus vendors primarily identified {tier_2_av_most_dominant} activity."
        )

    if reputation_most_dominant:
        analysis["key_findings"].append(
            f"Reputation providers primarily identified {reputation_most_dominant} behavior."
        )


    for threat, engines in tier_1_av_support.items():
        engine_names = ", ".join(engines)

        analysis["key_findings"].append(
            f"{engine_names} trusted antivirus vendors identified {threat} activity."
        )

        analysis["evidence"].append({
            "type": "av",
            "threat": threat,
            "engines": engines
        })


    for threat, engines in reputation_support.items():
        engine_names = ", ".join(engines)

        analysis["key_findings"].append(
            f"{engine_names} identified {threat} behavior."
        )
        analysis["evidence"].append({
            "type": "reputation",
            "threat": threat,
            "engines": engines
        })



    if analysis["av_clean"] >= 2:
        analysis["key_findings"].append(
            f"{analysis['av_clean']} trusted antivirus vendors classified the URL as clean."
        )

    if analysis["conflicting_assesment"] == True:
        analysis["key_findings"].append(
            "Security providers produced conflicting assessments."
        )

    print("Analysis: ", analysis)
    
    
    return analysis





