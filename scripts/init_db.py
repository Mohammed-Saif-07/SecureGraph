from core.graph_engine import graph
from core.sql_db import init_db


if __name__ == "__main__":
    init_db()
    graph.setup_schema()
    graph.seed_demo_graph()
    print("SecureGraph SQL and Neo4j schemas initialized.")
