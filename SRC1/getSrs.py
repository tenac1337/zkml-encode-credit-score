import asyncio
import ezkl
import os

async def run_get_srs():
    """Runs EZKL get_srs with async handling."""
    settings_path = os.path.abspath("settings.json")
    onnx_path = os.path.abspath("credit_model.onnx")
    print("🔹 Running EZKL get_srs()...")
    await ezkl.get_srs("settings.json")
    print("✅ SRS setup complete!")


async def generate_settings():
    """Generate settings.json before calling get_srs()."""
    print("🔹 Generating settings.json...")
    settings_path = os.path.abspath("settings.json")
    onnx_path = os.path.abspath("credit_model.onnx")
    # await ezkl.gen_settings("settings.json")
    print(f"🔹 Generating settings.json at {settings_path} using {onnx_path}...")

    # ✅ Use full paths to avoid directory issues
    # ✅ Run EZKL with debugging enabled
    try:
        await ezkl.gen_settings(settings_path, onnx_path)
        print("✅ settings.json successfully generated!")
    except RuntimeError as e:
        print(f"❌ ERROR: {e}")
        print("🔹 Possible Fix: Try simplifying the model or reinstalling EZKL.")
        raise

    print("✅ settings.json successfully generated!")

asyncio.run(generate_settings())
# ✅ Force proper async execution
# asyncio.run(run_get_srs())
