# neo4mitre

1. Import MITRE for ICS as JSON
2. Export JSON to neo4j

## To do

- Make sure it's getting everything in JSON
- Enrich nodes with more information like references, aliases, dates, etc.
- use logging lib
- use env password os.getenv instead of hardcoded
- Look into better using neo4j functions to avoid writing out commands

## Instructions

1. Create a neo4j db with password "neo4MITRE"
2. Run script in venv
3. Check your graph by running:

`MATCH (g)-[r]->(n) WHERE g.name = "APT1" RETURN g,r,n`

`MATCH (n {name:"Lazarus Group"})-[r]-(n2) RETURN n,r,n2`
