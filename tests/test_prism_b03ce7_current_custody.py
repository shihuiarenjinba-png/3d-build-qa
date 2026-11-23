"""Latest Prism b03ce7 custody fixture, independent of historical PR22/23."""
import hashlib
import io
import json
import os
from pathlib import Path
import unittest
import zipfile

SOURCE = "b03ce7b16c3f75c04fe20fdda224c45849eeba0d"
REQUEST = "3d-prism-route-3d-b03ce7b16c3f"
ARTIFACT_ID = 14797309778
RUN_ID = 43794658086
ZIP_SHA = "e2573b9ab11afde6ab6ec7417c23438581620a08bb9dcff76d792a2b5592ccac"
ZIP_SIZE = 37795977
MEMBERS = {
    "candidate.exe": (84214784, "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"),
    "candidate.pck": (6987584, "b7abc0f9caf2e505a1dcaf834b4cb897d8f00df4060c31708914e8bb4f3d5666"),
    "export-evidence.json": (680, "442d2c9070e017adf1c0ceaa96ba607f470c0f147176671f8a844122aca4d5bd"),
}
CONDITIONS = tuple((lang, dpi) for lang in ("ja", "en") for dpi in (100, 125, 150))
FRAMES = ("guide", "active", "scan", "trap", "outcome", "retry")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_bytes(data):
    if len(data) != ZIP_SIZE or digest(data) != ZIP_SHA:
        raise ValueError("canonical ZIP bytes mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if len(infos) != 3 or {x.filename for x in infos} != set(MEMBERS):
            raise ValueError("ZIP member set/duplicate mismatch")
        if z.testzip() is not None:
            raise ValueError("ZIP CRC mismatch")
        for name, (size, sha) in MEMBERS.items():
            info = z.getinfo(name)
            if info.file_size != size or digest(z.read(name)) != sha:
                raise ValueError("member bytes mismatch: " + name)
        manifest = json.loads(z.read("export-evidence.json"))
        for key, expected in {
            "source_sha": SOURCE, "factory_build_head": SOURCE,
            "request_id": REQUEST, "source_repository": "shihuiarenjinba-png/3d-game-factory",
            "slug": "prism-route-3d", "product_type": "GAME_3D",
            "exe_sha256": MEMBERS["candidate.exe"][1],
            "pck_sha256": MEMBERS["candidate.pck"][1],
            "exe_size_bytes": MEMBERS["candidate.exe"][0],
            "pck_size_bytes": MEMBERS["candidate.pck"][0],
        }.items():
            if manifest.get(key) != expected:
                raise ValueError("manifest mismatch: " + key)
    return True


def empty_capture():
    return {"source_sha": SOURCE, "request_id": REQUEST, "artifact_id": ARTIFACT_ID,
            "physical_status": "HOLD", "sale_ready": False,
            "sessions": [{"language": lang, "dpi_percent": dpi, "physical_verified": False,
                          "screenshots": {frame: f"{lang}-{dpi}-{frame}.png" for frame in FRAMES}}
                         for lang, dpi in CONDITIONS]}


class LatestFixtureTests(unittest.TestCase):
    def test_six_conditions_36_unique_images_remain_hold(self):
        x = empty_capture()
        self.assertEqual(len(x["sessions"]), 6)
        self.assertEqual(len({v for s in x["sessions"] for v in s["screenshots"].values()}), 36)
        self.assertFalse(x["sale_ready"])
        self.assertTrue(all(not s["physical_verified"] for s in x["sessions"]))

    def test_wrong_zip_fails_closed(self):
        with self.assertRaises(ValueError):
            verify_bytes(b"historical or synthetic bytes")

    def test_exact_bytes_when_supplied(self):
        path = os.environ.get("PRISM_B03_CANONICAL_ZIP")
        if not path:
            self.skipTest("canonical ZIP not supplied; NO BYTE PASS claimed")
        self.assertTrue(verify_bytes(Path(path).read_bytes()))


if __name__ == "__main__":
    unittest.main()
