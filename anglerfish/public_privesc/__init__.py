"""Anglerfish public→privesc bait pack — sensor-wired.

3-beat chain: public leak → weak login → local escalate → gotcha.
Hard stops: no real RCE, no outbound, allowlisted shell stubs only.
php2shell lure stays parallel and untouched.

Live: imported by phpapp via sensor_adapter.try_handle.
Standalone smoke: public_privesc.handler.PrivescHandler + local server.py.
"""

__version__ = "0.2.0-wired"
