from neo4j import GraphDatabase
import requests

# MITRE
mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Conn
uri = "bolt://localhost:7687"
username = "?"
db_name = "neo4j"
auth = (db_name, "neo4MITRE")
driver = GraphDatabase.driver(uri, auth=auth)

## TO DO
# Enrich nodes with more information
# use logging lib
# use env password os.getenv instead of hardcoded
# Look into sanitising / using better neo4j functions to avoid writing out commands
# Make relationships with aliases (i.e. APT1 "known as")

# Return JSON MITRE ATT&CK
def get_mitre(url):
    print(f'Retrieving MITRE JSON file from {mitre_url}')
    mitre_json = requests.get(url).json()
    print(f'... done! Found {len(mitre_json["objects"])} unique items')
    return mitre_json


# Delete existing nodes
def delete_graph():
    print(f'Deleting everything on {uri}...')

    records, _, _ = driver.execute_query(
        "MATCH (n) DETACH DELETE n RETURN count(n) AS deleted_count"
    )

    print(f"... done! {records[0]["deleted_count"]} nodes deleted")


def build_label(name):
    if name.startswith('intrusion-set'):
        return 'Group'
    if name.startswith('malware'):
        return 'Software'
    if name.startswith('tool'):
        return 'Tool'
    if name.startswith('attack-pattern'):
        return 'Technique'
    if name.startswith('course-of-action'):
        return 'Technique'
    else:
        return 'Unknown'


# Use https://github.com/neo4j-examples/movies-python-bolt/blob/main/movies_sync.py as good code for driver
def build_objects(mitre_obj):
    print("Building objects in Neo4j...")
    for obj in mitre_obj:

        # Cypher doesn't accept variables with "-"
        label = build_label(obj["type"])

        if obj.get('name'):
            # Build nodes for each item
            driver.execute_query(
                f'MERGE (n:{label} {{name: $name, id: $id}})', name=obj["name"], id=obj["id"]
            )
        if obj.get('relationship_type'):
            relationship_type = obj["relationship_type"].replace("-", "_")
            driver.execute_query(f"""
                MATCH (a), (b) WHERE a.id = $source_id AND b.id = $target_id
                MERGE (a)-[:{relationship_type}]->(b) """, 
                source_id=obj["source_ref"], 
                target_id=obj["target_ref"]
            )

    print("... done! Objects built in Neo4j! Check your graph.")


def main():
    mitre_json = get_mitre(mitre_url)["objects"]

    try:
        # Delete existing data
        delete_graph() # Doesn't really need when MERGEing

        # Build objects
        build_objects(mitre_json)
    finally:
        driver.close()

if __name__ == "__main__":
    main()
