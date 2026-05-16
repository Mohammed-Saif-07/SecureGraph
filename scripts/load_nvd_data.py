import asyncio
from core.ingestion.nvd_ingester import ingest_nvd


if __name__ == "__main__":
    print(asyncio.run(ingest_nvd(max_pages=1)))
