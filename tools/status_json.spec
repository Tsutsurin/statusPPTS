"""Рецепт сборки status_json.exe через PyInstaller (папка с программой)."""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve().parent

hiddenimports = [
    'status.adapters.name_normalizer',
    "status.adapters.io.excel_reader_adapter",
    "status.adapters.ml.sentence_transformer_adapter",
    "status.adapters.matchers.rapidfuzz_adapter",
    "status.adapters.db.sqlite_repository",
    "status.adapters.db.sqlite_schema",
    *collect_submodules("status.core"),
    *collect_submodules("rapidfuzz"),
]

a = Analysis(
    [str(ROOT / "tools" / "status_json.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PySide6", "fastapi", "uvicorn", "starlette", "anyio", "onnxruntime",
              "transformers", "torch", "sentence_transformers", "tkinter"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="status_json",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="status_json",
)
