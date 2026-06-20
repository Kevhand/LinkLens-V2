import json
import re
import faiss
import os
from numpy import rint
import torch
import time 
import requests
import re
from collections import Counter, defaultdict

def clean_description(description):
    description = re.sub(r"\(Citations:.*?\)", "", description)

    description = re.sub(r"<.*?>", "", description)

    description = re.sub(r"\s+", " ", description ).strip()

    return description


def clean_link(text):
    if not text:
        return ""


    text = re.sub(
        r"\[([^\]]+)\]\([^)]+\)",
        r"\1",
        text
    )

    return text.strip()



def load_data():
    files = [
        "enterprise-attack-1.0.json",
        "enterprise-attack-2.0.json",
        "enterprise-attack-3.0.json",
        "enterprise-attack-4.0.json",
        "enterprise-attack-5.0.json",
        "enterprise-attack-5.1.json",
        "enterprise-attack-5.2.json",
        "enterprise-attack-6.0.json",
        "enterprise-attack-6.1.json",
        "enterprise-attack-6.2.json",
        "enterprise-attack-6.3.json",
        "enterprise-attack-7.0.json",
        "enterprise-attack-7.1.json",
        "enterprise-attack-7.2.json",
        "enterprise-attack-8.0.json",
        "enterprise-attack-8.1.json",
        "enterprise-attack-8.2.json",
        "enterprise-attack-9.0.json",
        "enterprise-attack-10.0.json",
        "enterprise-attack-10.1.json",
        "enterprise-attack-11.0.json",
        "enterprise-attack-11.1.json",
        "enterprise-attack-11.2.json",
        "enterprise-attack-11.3.json",
        "enterprise-attack-12.0.json",
        "enterprise-attack-12.1.json",
        "enterprise-attack-13.0.json",
        "enterprise-attack-13.1.json",
        "enterprise-attack-14.0.json",
        "enterprise-attack-14.1.json",
        "enterprise-attack-15.0.json",
        "enterprise-attack-15.1.json",
        "enterprise-attack-16.0.json",
        "enterprise-attack-16.1.json",
        "enterprise-attack-17.0.json",
        "enterprise-attack-17.1.json",
        "enterprise-attack-18.0.json",
        "enterprise-attack-18.1.json",
        "enterprise-attack-19.0.json",
        "enterprise-attack-19.1.json",
    ]


    files_mobile = [
        "mobile-attack-1.0.json",
        "mobile-attack-2.0.json",
        "mobile-attack-3.0.json",
        "mobile-attack-4.0.json",
        "mobile-attack-5.0.json",
        "mobile-attack-5.1.json",
        "mobile-attack-5.2.json",
        "mobile-attack-6.0.json",
        "mobile-attack-6.1.json",
        "mobile-attack-6.2.json",
        "mobile-attack-6.3.json",
        "mobile-attack-7.0.json",
        "mobile-attack-7.1.json",
        "mobile-attack-7.2.json",
        "mobile-attack-8.0.json",
        "mobile-attack-8.1.json",
        "mobile-attack-8.2.json",
        "mobile-attack-9.0.json",
        "mobile-attack-10.0.json",
        "mobile-attack-10.1.json",
        "mobile-attack-11.0-beta.json",
        "mobile-attack-11.1-beta.json",
        "mobile-attack-11.2-beta.json",
        "mobile-attack-11.3.json",
        "mobile-attack-12.0.json",
        "mobile-attack-12.1.json",
        "mobile-attack-13.0.json",
        "mobile-attack-13.1.json",
        "mobile-attack-14.0.json",
        "mobile-attack-14.1.json",
        "mobile-attack-15.0.json",
        "mobile-attack-15.1.json",
        "mobile-attack-16.0.json",
        "mobile-attack-16.1.json",
        "mobile-attack-17.0.json",
        "mobile-attack-17.1.json",
        "mobile-attack-18.0.json",
        "mobile-attack-18.1.json",
        "mobile-attack-19.0.json",
        "mobile-attack-19.1.json"
        
    ]



    files_ics = [
        "ics-attack.json",
        "ics-attack-8.0.json",
        "ics-attack-8.1.json",
        "ics-attack-8.2.json",
        "ics-attack-9.0.json",
        "ics-attack-10.0.json",
        "ics-attack-10.1.json",
        "ics-attack-11.0.json",
        "ics-attack-11.1.json",
        "ics-attack-11.2.json",
        "ics-attack-11.3.json",
        "ics-attack-12.0.json",
        "ics-attack-12.1.json",
        "ics-attack-13.0.json",
        "ics-attack-13.1.json",
        "ics-attack-14.0.json",
        "ics-attack-14.1.json",
        "ics-attack-15.0.json",
        "ics-attack-15.1.json",
        "ics-attack-16.0.json",
        "ics-attack-16.1.json",
        "ics-attack-17.0.json",
        "ics-attack-17.1.json",
        "ics-attack-18.0.json",
        "ics-attack-18.1.json",
        "ics-attack-19.0.json",
        "ics-attack-19.1.json"
    ]



    all_objects = []


    for File in files:
        with open(f"assistant/Enterprise/{File}", "r") as file:
            data = json.load(file)
            all_objects.extend(data["objects"])


    for File in files_mobile:
        with open(f"assistant/Mobile/{File}", "r") as file:
            data = json.load(file)
            all_objects.extend(data["objects"])

    for File in files_ics:
        with open(f"assistant/ICS/{File}", "r") as file:
            data = json.load(file)
            all_objects.extend(data["objects"])



    attack_patterns = {}
    mitigation = {}
    intrusion_set = {}
    malware = {}

    for objects in all_objects:
        if objects["type"] == "attack-pattern":
            name = objects.get("name", "")
            description = objects.get("description", "")

            description = clean_description(description)

            description = re.split(r"Detection:|Platforms:|Data Sources:|Permissions Required:", description)[0]


            stixx_id = objects.get("id", "")

            external_id = objects.get("external_references")[0].get("external_id", "")


            attack_patterns[objects["id"]] = {
                "id": stixx_id,
                "name": name,
                "description" : description,
                "mitigation": [],
                "intrusion_set": [],
                "malware": []
            }


    for objects in all_objects:
        if objects["type"] == "malware":
            malware[objects["id"]] = {
                "name": objects.get("name", ""),
                "description": clean_description(clean_link(objects.get("description", ""))),
                "attack_pattern": [],
                "intrusion_set": []

            }

    for objects in all_objects:
        if objects["type"] == "relationship":
            if objects.get("relationship_type") == "uses":
                source_ref = objects["source_ref"]
                target_ref = objects["target_ref"]

                if (source_ref in malware and target_ref in attack_patterns):
                    malware_name = malware[source_ref]["name"]
                    malware_description = malware[source_ref]["description"]
                    malware_description = clean_description(malware_description)
                    malware_description = clean_link(malware_description)


                    existing_ids = {x["id"] for x in attack_patterns[target_ref]["malware"]}

                    if target_ref in attack_patterns and source_ref not in existing_ids:
                        attack_patterns[target_ref]["malware"].append({
                            "id": source_ref,
                            "name": malware_name,
                            "description": malware_description
                        })

                    existing_ids = {x["id"] for x in malware[source_ref]["attack_pattern"]}
                    if target_ref in attack_patterns and target_ref not in existing_ids:
                        malware[source_ref]["attack_pattern"].append({
                            "id": target_ref,
                            "name": attack_patterns[target_ref]["name"],
                            "description": attack_patterns[target_ref]["description"]
                        })



    for objects in all_objects:
        if objects["type"] == "intrusion-set":
            intrusion_set[objects["id"]] = {
                "name": objects.get("name", ""),
                "description": clean_description(clean_link(objects.get("description", ""))),
                "attack_pattern": [],
                "malware": []
            }


    for objects in all_objects:
        if objects["type"] == "relationship":
            if objects.get("relationship_type") == "uses":
                source_ref = objects["source_ref"]
                target_ref = objects["target_ref"]


                if (source_ref in intrusion_set and target_ref in attack_patterns):
                    intrusion_set_name = intrusion_set[source_ref]["name"]
                    intrusion_set_description = clean_description(intrusion_set[source_ref]["description"])
                    intrusion_set_description = clean_link(intrusion_set_description)


                    existing_ids = {x["id"] for x in attack_patterns[target_ref]["intrusion_set"]}

                    if target_ref in attack_patterns and source_ref not in existing_ids:
                        attack_patterns[target_ref]["intrusion_set"].append({
                            "id": source_ref,
                            "name": intrusion_set_name,
                            "description": intrusion_set_description
                        })
                    existing_ids = {x["id"] for x in intrusion_set[source_ref]["attack_pattern"]}
                    if target_ref not in existing_ids:
                        intrusion_set[source_ref]["attack_pattern"].append({
                        "id": target_ref,
                        "name": attack_patterns[target_ref]["name"],
                            "description": attack_patterns[target_ref]["description"]
                    })
                if(source_ref in intrusion_set and target_ref in malware):
                    malware_name = malware[target_ref]["name"]
                    malware_description = malware[target_ref]["description"]


                    existing_ids = {x["id"] for x in intrusion_set[source_ref]["malware"]}

                    if target_ref in malware and target_ref not in existing_ids:
                        intrusion_set[source_ref]["malware"].append({
                            "id": target_ref,
                            "name": malware[target_ref]["name"],
                            "description": malware[target_ref]["description"]
                            
                        })
                    existing_ids = {x["id"] for x in malware[target_ref]["intrusion_set"]}
                    if source_ref not in existing_ids:
                        malware[target_ref]["intrusion_set"].append({
                            "id": source_ref,
                            "name": intrusion_set[source_ref]["name"],
                            "description": intrusion_set[source_ref]["description"]
                        })



    for objects in all_objects:
        if objects["type"] == "course-of-action":
            mitigation[objects["id"]] = {
                "name" : objects.get("name", ""),
                "description": objects.get("description", ""),
                "attack_pattern": []
            }


    for objects in all_objects:
        if objects["type"] == "relationship":
            if objects.get("relationship_type") == "mitigates":
                source_ref = objects["source_ref"]
                target_ref = objects["target_ref"]


                if (source_ref in mitigation and target_ref in attack_patterns):
                    mitigation_name = mitigation[source_ref]["name"]
                    mitigation_description = mitigation[source_ref]["description"]
                    mitigation_description = clean_description(mitigation_description)

                    existing_ids = {x["id"] for x in attack_patterns[target_ref]["mitigation"]}

                    if target_ref in attack_patterns and source_ref not in existing_ids:

                        attack_patterns[target_ref]["mitigation"].append({
                            "id": source_ref,
                            "name": mitigation_name,
                            "description": mitigation_description
                        })

                    existing_ids = {x["id"] for x in mitigation[source_ref]["attack_pattern"]}
                    if target_ref not in existing_ids:
                        mitigation[source_ref]["attack_pattern"].append({
                            "id": target_ref,
                            "name": attack_patterns[target_ref]["name"],
                            "description": attack_patterns[target_ref]["description"]
                        })
    
    
    print(len(attack_patterns))
    print(len(malware))
    print(len(intrusion_set))
    print(len(mitigation))

    
    return attack_patterns, malware, intrusion_set, mitigation



"""
def create_index(chunk, filename):
  text = [c["text"] for c in chunk]

  embeddings = embedding_model.encode(
      text,
      convert_to_tensor = True,
      device = device
  )


  embeddings_np = embeddings.cpu().numpy().astype("float32")

  faiss.normalize_L2(embeddings_np)

  index = faiss.IndexFlatIP(embeddings_np.shape[1])

  index.add(embeddings_np)

  os.makedirs("indices", exist_ok = True)

  faiss.write_index(index, filename)
"""

def create_embeddings(attack_patterns, malware, intrusion_set, mitigation):
  attack_chunk = []
  malware_chunk = []
  intrusion_chunk = []
  mitigation_chunk = []


  for values in attack_patterns.values():
    attack_chunk.append({
        "type": "Attack Pattern",
        "id": values["id"],
        "name": values["name"],
        "description": values["description"],

        "malware": values["malware"],
        "intrusion_set": values["intrusion_set"],
        "mitigation": values["mitigation"],

        "text": f"""
        Entity Type: Attack Pattern

        Entity Name:
        Name: {values["name"]}

        Entity Description:
        Description: {values["description"]}
        """
    })

  for malware_id, values in malware.items():
    malware_chunk.append({
        "type": "Malware",
        "id": malware_id,

        "name": values["name"],
        "description": values["description"],

        "attack_pattern": values["attack_pattern"],
        "intrusion_set": values["intrusion_set"],

        "text": f"""
        Entity Type: Malware

        Entity Name:
        Malware Name: {values["name"]}

        Entity Description:
        Malware Description: {values["description"]}
        """
    })
  
  for intrusion_id, values in intrusion_set.items():
    intrusion_chunk.append({
        "type": "Intrusion Set",
        "id": intrusion_id,

        "name": values["name"],
        "description": values["description"],

        "attack_pattern": values["attack_pattern"],
        "malware": values["malware"],

        "text": f"""
        Entity Type: Intrusion Set

        Entity Name:
        Intrusion Set Name: {values["name"]}

        Entity Description:
        Intrusion Set Description: {values["description"]}
        """
    })
  
  for mitigation_id, values in mitigation.items():
    mitigation_chunk.append({
        "type": "Mitigation",
        "id": mitigation_id,

        "name": values["name"],
        "description": values["description"],

        "attack_pattern": values["attack_pattern"],

        "text": f"""
        Entity Type: Mitigation

        Entity Name:
        Mitigation Name: {values["name"]}

        Entity Description:
        Mitigation Description: {values["description"]}
        """
    })
  

  entity_chunk = (
      attack_chunk +
      malware_chunk +
      intrusion_chunk +
      mitigation_chunk
  )


  print("Entity Chunks: ", len(entity_chunk))


  return entity_chunk



start = time.time()

attack_patterns, malware, intrusion_set, mitigation = load_data()

print("CREATED attack_pattern, malware, intrusion_set, mitigation in:  ", round(time.time() - start, 2), "seconds")




start = time.time()
entity_chunk = create_embeddings(attack_patterns=attack_patterns, malware=malware, intrusion_set=intrusion_set, mitigation=mitigation)

print("CREATED entity_chunk in:  ", round(time.time() - start, 2), "seconds")


def normalize_results(result):
  if not result:
    return None

  result = result.lower().strip()
  result = re.sub(r'[^a-z0-9 ]', ' ', result)

  tokens = set(result.split())

  threat_patterns = {
      "ransomware": r"ransom|cryptolocker|wannacry|lockbit",
      "phishing": r"phish|credential|fake[ ]login|fraud|scam",
      "infostealer": r"stealer|infostealer|password|keylogger|spyware|trojan[ ]spy",
      "trojan": r"trojan|trj|backdoor|bd|rat|remote[ ]access",
      "downloader": r"downloader|dropper|loader|stager",
      "cryptominer": r"miner|coinminer|cryptominer|xmr",
      "botnet": r"botnet|bot|mirai|ddos",
      "worm": r"worm|conficker|autorun",
      "rootkit": r"rootkit|rootk|kernel",
      "adware": r"adware|pup|pua|unwanted|grayware|greyware|riskware|applicunwnt",
      "exploit": r"exploit|cve|weaponized|vulnerability",
      "exploit-kit": r"exploit[ ]kit",
      "banker": r"banker|banking|bankbot",
      "wiper": r"wiper|destructive|driveclean",
      "spyware": r"spyware|monitor",
      "suspicious": r"suspicious|heur|unclassified"
  }

  for category, pattern in threat_patterns.items():
      if re.search(pattern, result):
          return category

  if "malware" in tokens or "malicious" in tokens:
      return "malware"

  return "other"


