"""
©AngelaMos | 2026
metadata.py
"""

import hashlib
import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.model_metadata import ModelMetadata

logger = logging.getLogger(__name__)

MODEL_TYPES: dict[str, str] = {
    "ae.onnx": "autoencoder",
    "rf.onnx": "random_forest",
    "if.onnx": "isolation_forest",
}

VERSION_HASH_LENGTH = 12


def compute_model_version(artifact_path: Path) -> str:
    """
    Compute a 12-char hex version string from the SHA-256 hash of a file
    """
    sha = hashlib.sha256(artifact_path.read_bytes())
    return sha.hexdigest()[:VERSION_HASH_LENGTH]


async def save_model_metadata(
    session: AsyncSession,
    model_dir: Path,
    training_samples: int,
    metrics: dict[str, object],
    mlflow_run_id: str | None = None,
    threshold: float | None = None,
) -> list[ModelMetadata]:
    """
    Persist metadata for all 3 model types, deactivating previous active versions
    """
    rows: list[ModelMetadata] = []

    for filename, model_type in MODEL_TYPES.items():
        artifact_path = model_dir / filename
        version = compute_model_version(artifact_path)

        result = await session.execute(
            select(ModelMetadata).where(
                ModelMetadata.model_type == model_type,  # type: ignore[arg-type]
                ModelMetadata.is_active == True,  # type: ignore[arg-type]  # noqa: E712
            ))
        for old in result.scalars().all():
            old.is_active = False
        await session.flush()

        row = ModelMetadata(
            model_type=model_type,
            version=version,
            training_samples=training_samples,
            metrics=metrics,
            artifact_path=str(artifact_path),
            is_active=True,
            mlflow_run_id=mlflow_run_id,
            threshold=threshold,
        )
        session.add(row)
        rows.append(row)

    await session.commit()

    logger.info(
        "Saved metadata for %d models (samples=%d)",
        len(rows),
        training_samples,
    )

    return rows
