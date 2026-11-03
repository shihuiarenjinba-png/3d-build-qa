"""Independent read-only PR23 real-PCK modal layout gate; never physical Windows QA."""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

SOURCE = "a8781693e8477ac1f96fff1c648ce48e39da6f42"
REQUEST = "3d-prism-route-3d-a8781693e847"
PCK_SHA = "PCK_SHA_PENDING_EXPORT"
CAPTURE = "GODOT_4_3_MESA_XVFB_PR23_SOFTWARE_LAYOUT_ONLY"
SIZES = ("1024x768", "1024x720")
DPIS = (100, 125, 150)
LOCALES = ("en", "ja")

class LayoutHold(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise LayoutHold(why)

def overlaps(a, b):
    a, b = a["rect"], b["rect"]
    w = max(0.0, min(a["x"]+a["width"], b["x"]+b["width"]) - max(a["x"], b["x"]))
    h = max(0.0, min(a["y"]+a["height"], b["y"]+b["height"]) - max(a["y"], b["y"]))
    return w * h

def inside(a, b, margin=0.0):
    a, b = a["rect"], b["rect"]
    return (a["x"] >= b["x"]+margin-1.5
            and a["y"] >= b["y"]+margin-1.5
            and a["x"]+a["width"] <= b["x"]+b["width"]-margin+1.5
            and a["y"]+a["height"] <= b["y"]+b["height"]-margin+1.5)

def check_record(r, size, dpi, locale):
    require(r.get("schema_version") == 1 and r.get("source_sha") == SOURCE
            and r.get("request_id") == REQUEST and r.get("pck_sha256") == PCK_SHA,
            "old PR22 or mismatched source/request/PCK")
    require(r.get("capture_kind") == CAPTURE and r.get("requested_window") == size
            and r.get("simulated_dpi_percent") == dpi and r.get("locale") == locale,
            "scenario / capture kind mismatch")
    require(r.get("physical_windows_gui") == "HOLD"
            and r.get("human_first_30s") == "HOLD"
            and r.get("human_real_time_90s") == "HOLD"
            and r.get("sale_ready") is False
            and r.get("store_submission_allowed") is False,
            "software screenshots cannot assert physical, human or Store PASS")
    require(abs(r.get("content_scale_factor", -100) - dpi/100) < 0.01,
            "DPI model was not applied")
    viewport = r.get("logical_viewport")
    require(isinstance(viewport, dict) and viewport["x"] == 0 and viewport["y"] == 0
            and abs(viewport["width"] - round(1024*100/dpi)) <= 1
            and abs(viewport["height"] - round(768*100/dpi)) <= 1,
            "unexpected logical viewport / DPI model")
    w,h = ((960,720) if size=="1024x720" else (1024,768))
    require((r.get("actual_image_width"),r.get("actual_image_height")) == (w,h)
            and (r.get("active_image_width"),r.get("active_image_height")) == (w,h),
            "software image dimensions / 4:3 workarea scaling mismatch")
    nodes, active = r.get("nodes"), r.get("active_nodes")
    require(isinstance(nodes, dict) and isinstance(active, dict), "missing control geometry")
    for name in ("guide","title","details","start","guide_language"):
        require(nodes[name]["visible"] is True and nodes[name]["inside_viewport"] is True,
                "guide, language or Start clipped/invisible: "+name)
    require(nodes["start"]["disabled"] is False and nodes["guide_language"]["disabled"] is False
            and "Enter" in nodes["start"]["text"]
            and ("English" in nodes["guide_language"]["text"] if locale=="ja"
                 else "日本語" in nodes["guide_language"]["text"]),
            "modal Start / click language switch unusable")
    require(nodes["guide"]["rect"]["x"] >= 14.0
            and viewport["width"] - nodes["guide"]["rect"]["x"] - nodes["guide"]["rect"]["width"] >= 14.0,
            "responsive guide side margin too small")
    require(inside(nodes["start"],nodes["guide"])
            and inside(nodes["guide_language"],nodes["guide"])
            and inside(nodes["title"],nodes["guide"])
            and inside(nodes["details"],nodes["guide"]),
            "modal content spills outside guide")
    for name in ("title","details"):
        require(nodes[name]["visible_line_count"] == nodes[name]["line_count"]
                and nodes[name]["line_count"] >= 1,
                "guide text clipped: "+name)
    require(nodes["details"]["line_count"] == 4, "four-line first-run guide no longer fits")
    require(nodes["top_hud"]["visible"] is False and nodes["bottom_hud"]["visible"] is False
            and nodes["status"]["visible"] is False and nodes["hint"]["visible"] is False,
            "legacy gameplay HUD peeks through first-run modal")
    for name in ("top_hud","bottom_hud","status","scan","hint"):
        require(active[name]["visible"] is True and active[name]["inside_viewport"] is True,
                "gameplay HUD not restored or clipped after Start: "+name)
    for name in ("status","scan"):
        require(active[name]["text_width_unwrapped"] <= active[name]["rect"]["width"]+2.0,
                "unwrapped HUD text clipped: "+name)
    require(active["hint"]["visible_line_count"] == active["hint"]["line_count"]
            and 1 <= active["hint"]["line_count"] <= 2,
            "bottom HUD hint clipped after Start")
    return {"size":size,"dpi":dpi,"locale":locale,"start_visible":True,
            "language_click_visible":True,"hud_hidden_before_start":True,
            "hud_restored_after_start":True,"guide_margin_logical_px":nodes["guide"]["rect"]["x"]}

def png_digest(path: Path, expected_size):
    require(path.is_file() and not path.is_symlink(), "missing PNG "+str(path))
    data=path.read_bytes()
    require(len(data)>1024 and data[:8]==b"\x89PNG\r\n\x1a\n", "invalid PNG")
    pos, dims, idat, end = 8, None, False, False
    while pos < len(data):
        require(pos+12<=len(data), "truncated PNG")
        length=struct.unpack_from(">I",data,pos)[0]
        require(length<=30_000_000 and pos+12+length<=len(data), "unsafe PNG chunk")
        kind=data[pos+4:pos+8]
        payload=data[pos+8:pos+8+length]
        crc=struct.unpack_from(">I",data,pos+8+length)[0]
        require(zlib.crc32(kind+payload)&0xffffffff==crc, "PNG CRC mismatch")
        if kind==b"IHDR":
            require(dims is None and length==13, "invalid PNG IHDR")
            dims=struct.unpack_from(">II",payload)
        if kind==b"IDAT": idat=True
        if kind==b"IEND":
            require(length==0 and pos+12==len(data), "trailing PNG bytes")
            end=True
            break
        pos+=12+length
    require(dims==expected_size and idat and end, "PNG size or IEND mismatch")
    return hashlib.sha256(data).hexdigest()

def verify_bundle(root: Path, factory: dict):
    require(factory.get("source_sha")==SOURCE and factory.get("request_id")==REQUEST
            and factory.get("pck_sha256")==PCK_SHA and factory.get("zip_crc_verified") is True,
            "independent exact Factory byte preflight missing")
    cases, frames = [], {}
    for size in SIZES:
        for dpi in DPIS:
            for locale in LOCALES:
                name=f"{size}_{dpi}_{locale}"
                r=json.loads((root/"receipts"/(name+".json")).read_text(encoding="utf-8"))
                cases.append(check_record(r,size,dpi,locale))
                expected=(960,720) if size=="1024x720" else (1024,768)
                a=png_digest(root/"screenshots"/(name+".png"),expected)
                b=png_digest(root/"screenshots"/(name+"_active.png"),expected)
                require(a!=b,"Start did not visibly dismiss guide")
                frames[name]={"guide_sha256":a,"active_sha256":b,
                              "width":expected[0],"height":expected[1]}
    return {"status":"PR23_MODAL_LAYOUT_SOFTWARE_PASS_NOT_PHYSICAL",
            "source_sha":SOURCE,"request_id":REQUEST,"pck_sha256":PCK_SHA,
            "scenario_count":len(cases),"software_image_count":len(frames)*2,
            "cases":cases,"images":frames,
            "physical_windows_gui":"HOLD","human_first_30s":"HOLD",
            "human_real_time_90s":"HOLD","identity_cas":"HOLD_36_OWNER",
            "sale_ready":False,"store_submission_allowed":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--preflight",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    try:
        result=verify_bundle(args.root,json.loads(args.preflight.read_text()))
        code=0
    except (OSError,ValueError,KeyError,TypeError,IndexError) as e:
        result={"status":"PR23_LAYOUT_HOLD","reason":str(e)[:240],
                "sale_ready":False,"store_submission_allowed":False}
        code=2
    args.out.write_text(json.dumps(result,indent=2,ensure_ascii=False,sort_keys=True)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("cases","images")}))
    return code

if __name__=="__main__":
    raise SystemExit(main())
