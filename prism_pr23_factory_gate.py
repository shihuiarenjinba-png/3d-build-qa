"""Fail-closed exact Factory PR23 ZIP/EXE/PCK/manifest preflight for layout QA."""
from __future__ import annotations
import argparse
import hashlib
import json
import stat
import zipfile
from pathlib import Path
from prism_sentinel_release_pck_content_gate import parse_pck, prohibited_resource

SOURCE="a8781693e8477ac1f96fff1c648ce48e39da6f42"
REQUEST="3d-prism-route-3d-a8781693e847"
RUN_ID=41553387129
ARTIFACT_ID=13193637844
ZIP_SHA="aac7f136e9343d73c7ea28da6c30d8edf90b029f8c1691c622be9d8024727d89"
ZIP_SIZE=37795975
MEMBERS={
 "candidate.exe":(84214784,"66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"),
 "candidate.pck":(6987568,"1b2bf98fdfec56ce6d82a246b6beaa5b3a5305516616122f0ea7aa001d2a8df1"),
 "export-evidence.json":(682,"bcdaad6b1be1eaa8352c140fd263134f6c681259201324bbdc0e1669873a3b67"),
}
OLD_PCK="d1363805e4f899b0a895b6c4153f3fc902d548529c0cc47579b965666fcd98ec"

class PR23FactoryHold(ValueError):
    pass

def require(ok,why):
    if not ok:
        raise PR23FactoryHold(why)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def no_duplicate_keys(pairs):
    out={}
    for key,value in pairs:
        require(key not in out,"duplicate JSON key")
        out[key]=value
    return out

def verify_archive(path:Path, extract_to:Path|None=None):
    require(path.is_file() and not path.is_symlink(),"Factory ZIP missing/symlink")
    require(path.stat().st_size==ZIP_SIZE and sha(path.read_bytes())==ZIP_SHA,
            "Factory ZIP SHA/size mismatch: old PR22 or tampering")
    with zipfile.ZipFile(path) as z:
        infos=z.infolist()
        require(len(infos)==3 and {i.filename for i in infos}==set(MEMBERS),
                "missing, extra or duplicate ZIP member")
        for i in infos:
            require(not i.is_dir() and not (i.flag_bits & 1)
                    and not stat.S_ISLNK(i.external_attr >> 16),
                    "unsafe ZIP entry")
            size,digest=MEMBERS[i.filename]
            require(i.file_size==size and sha(z.read(i))==digest,
                    "EXE/PCK/manifest independent SHA mismatch: "+i.filename)
        require(z.testzip() is None,"ZIP CRC mismatch")
        m=json.loads(z.read("export-evidence.json"),object_pairs_hook=no_duplicate_keys)
        expected={"schema_version":1,"slug":"prism-route-3d",
                  "product_type":"GAME_3D",
                  "source_repository":"shihuiarenjinba-png/3d-game-factory",
                  "source_branch":"codex/prism-first-run-modal-dpi-layout-20261103",
                  "source_sha":SOURCE,"factory_build_head":SOURCE,
                  "request_id":REQUEST}
        for key,value in expected.items():
            require(m.get(key)==value,"Factory manifest lineage mismatch: "+key)
        for kind in ("exe","pck"):
            name="candidate."+kind
            require(m.get(kind+"_path")==name
                    and m.get(kind+"_sha256")==MEMBERS[name][1]
                    and m.get(kind+"_size_bytes")==MEMBERS[name][0],
                    "Factory manifest member mismatch: "+kind)
        pck=z.read("candidate.pck")
        require(sha(pck)!=OLD_PCK,"historical PR22 PCK forbidden")
        resources=parse_pck(pck)
        names={r["path"] for r in resources}
        require(len(resources)==14
                and {"res://project.binary","res://scripts/main.gdc",
                     "res://scenes/main.tscn.remap"}<=names
                and not any(prohibited_resource(n) for n in names),
                "PCK compiled resource inventory invalid")
        if extract_to is not None:
            require(not extract_to.exists() or not any(extract_to.iterdir()),
                    "refuse overwrite of extracted evidence")
            extract_to.mkdir(parents=True,exist_ok=True)
            for name in MEMBERS:
                (extract_to/name).write_bytes(z.read(name))
    return {"status":"PR23_EXACT_FACTORY_BYTES_VERIFIED_RUNTIME_PENDING",
            "source_sha":SOURCE,"request_id":REQUEST,
            "pck_sha256":MEMBERS["candidate.pck"][1],
            "exe_sha256":MEMBERS["candidate.exe"][1],
            "manifest_sha256":MEMBERS["export-evidence.json"][1],
            "zip_sha256":ZIP_SHA,"zip_size_bytes":ZIP_SIZE,
            "factory_run_id":RUN_ID,"factory_artifact_id":ARTIFACT_ID,
            "zip_crc_verified":True,"pck_resource_count":len(resources),
            "physical_windows_gui":"HOLD","human_first_30s":"HOLD",
            "human_real_time_90s":"HOLD","sale_ready":False,
            "store_submission_allowed":False}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--archive",type=Path,required=True)
    ap.add_argument("--extract-to",type=Path)
    ap.add_argument("--out",type=Path,required=True)
    args=ap.parse_args()
    try:
        result=verify_archive(args.archive,args.extract_to)
        code=0
    except (OSError,ValueError,TypeError,KeyError,zipfile.BadZipFile) as e:
        result={"status":"PR23_FACTORY_HOLD","reason":str(e)[:240],
                "sale_ready":False,"store_submission_allowed":False}
        code=2
    args.out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True))
    return code

if __name__=="__main__":
    raise SystemExit(main())
