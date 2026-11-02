"""Use the portable source gate and host compiler from the exact locked Core release."""
import importlib.util
from core_sources import core_root

_helper = core_root() / "scripts/policy_source.py"
_spec = importlib.util.spec_from_file_location("allowit_core_policy_source", _helper)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
# Existing native admin consumers keep their imported names; the implementation stays in Core.
globals().update({name: value for name, value in vars(_module).items() if not name.startswith("__")})
