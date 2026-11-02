"""Fail-closed byte custody for the *new* Prism consumer PCK runtime QA.

The only positive verdict is that exact Factory ZIP bytes are ready for a
separate Godot PCK-loaded smoke. This never authenticates Identity or Store.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import stat
import zipfile

SOURCE = '9a73d0d56427b70fc0e0eba705a6be3e71c59390'
REQUEST = '3d-prism-route-3d-9a73d0d56427'
ARTIFACT_ID = 13126698701
RUN_ID = 41414464542
ZIP_SHA = '77e57ba5882d8ae82285c2274b908d525ae20ebd30c099d4801d19c2ed4ca2b4'
OLD_PCK = '3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03'
MEMBERS = {
    'candidate.exe': (84214784, '66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13'),
    'candidate.pck': (6970928, '8a4930cc55e2c628b524a108f057f516e40e04f57f73d377e70ded51de958e36'),
    'export-evidence.json': (681, 'fe91e728832a366e89696061c79e92017f6ce818cf8314ff788619462509e917'),
}
REQUIRED_RESOURCES = {
    'res://project.binary', 'res://scenes/main.tscn.remap',
    'res://scripts/main.gdc', 'res://scripts/game_logic.gdc',
    'res://scripts/save_store.gdc',
}

class ArtifactRuntimeError(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise ArtifactRuntimeError(reason)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def unique_pairs(pairs):
    out = {}
    for k,v in pairs:
        need(k not in out, 'duplicate JSON key')
        out[k]=v
    return out

def verify_archive(path: Path, *, extract_to: Path | None = None):
    from prism_sentinel_release_pck_content_gate import parse_pck, prohibited_resource
    need(path.is_file() and not path.is_symlink(), 'missing or symlink ZIP')
    need(path.stat().st_size == 37790250, 'ZIP size drift')
    need(sha(path.read_bytes()) == ZIP_SHA, 'ZIP SHA drift')
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        need(len(infos) == 3 and {i.filename for i in infos} == set(MEMBERS), 'ZIP member set/duplicate drift')
        for info in infos:
            need(not info.is_dir() and not (info.flag_bits & 1) and not stat.S_ISLNK(info.external_attr >> 16), 'unsafe ZIP entry')
            size, expected = MEMBERS[info.filename]
            need(info.file_size == size, 'member size drift: '+info.filename)
            need(sha(z.read(info)) == expected, 'member SHA drift: '+info.filename)
        need(z.testzip() is None, 'ZIP CRC drift')
        manifest = json.loads(z.read('export-evidence.json'), object_pairs_hook=unique_pairs)
        need(manifest.get('schema_version') == 1 and manifest.get('slug') == 'prism-route-3d' and
             manifest.get('product_type') == 'GAME_3D' and
             manifest.get('source_repository') == 'shihuiarenjinba-png/3d-game-factory' and
             manifest.get('source_branch') == 'codex/prism-consumer-board-visibility-20261102' and
             manifest.get('source_sha') == SOURCE and manifest.get('request_id') == REQUEST and
             manifest.get('factory_build_head') == SOURCE, 'new revision source/request/build drift')
        for kind in ('exe', 'pck'):
            name = 'candidate.'+kind
            need(manifest.get(kind+'_path') == name and
                 manifest.get(kind+'_sha256') == MEMBERS[name][1] and
                 manifest.get(kind+'_size_bytes') == MEMBERS[name][0], 'manifest '+kind+' drift')
        pck = z.read('candidate.pck')
        need(sha(pck) != OLD_PCK, 'old Sentinel PCK relabelled')
        entries = parse_pck(pck)
        paths = {e['path'] for e in entries}
        need(len(entries) == 14 and REQUIRED_RESOURCES <= paths, 'new PCK missing expected compiled game resources')
        need(not any(prohibited_resource(e['path']) for e in entries), 'internal resources in consumer PCK')
        need('res://assets/fonts/OFL.txt' in paths and
             any('res://assets/fonts/NotoSansJP.ttf' in p for p in paths) and
             any(p.endswith('.fontdata') for p in paths),
             'RELEASE_JP_FONT_CONTENT_HOLD: embedded font/license missing from real PCK')
        if extract_to is not None:
            extract_to.mkdir(parents=True, exist_ok=True)
            for name in MEMBERS:
                dest = extract_to / name
                need(not dest.exists() and not dest.is_symlink(), 'unsafe overwrite of extracted member')
                dest.write_bytes(z.read(name))
    return {
        'schema_version': 1,
        'receipt_type': 'PRISM_CONSUMER_REAL_ARTIFACT_RUNTIME_PREFLIGHT',
        'source_sha': SOURCE, 'request_id': REQUEST, 'factory_build_head': SOURCE,
        'factory_run_id': RUN_ID, 'factory_artifact_id': ARTIFACT_ID,
        'zip_sha256': ZIP_SHA, 'exe_sha256': MEMBERS['candidate.exe'][1],
        'pck_sha256': MEMBERS['candidate.pck'][1], 'manifest_sha256': MEMBERS['export-evidence.json'][1],
        'pck_resource_count': len(entries), 'pck_content_clean': True,
        'archive_bytes_verified_this_run': True, 'godot_pck_executed_this_run': False,
        'physical_windows_gui': 'DEFERRED_LOCAL_GATE', 'identity_cas': 'HOLD_36_OWNER',
        'package_version': 'HOLD', 'signed_product_msix': 'HOLD',
        'windows_all_auto_intake': 'HOLD', 'sale_ready': False,
        'store_submission_allowed': False,
        'status': 'EXACT_FACTORY_BYTES_VERIFIED_RUNTIME_PENDING',
    }

def finalize_runtime(preflight: dict, runtime: dict, screenshot_dir: Path):
    """Bind Godot PCK-loaded assertions and actual PNG files to pinned bytes."""
    need(preflight.get('receipt_type') == 'PRISM_CONSUMER_REAL_ARTIFACT_RUNTIME_PREFLIGHT' and
         preflight.get('archive_bytes_verified_this_run') is True and
         preflight.get('pck_sha256') == MEMBERS['candidate.pck'][1] and
         preflight.get('source_sha') == SOURCE and preflight.get('request_id') == REQUEST and
         preflight.get('sale_ready') is False and preflight.get('store_submission_allowed') is False,
         'runtime cannot be promoted from fixture or wrong artifact')
    need(runtime.get('schema_version') == 1 and
         runtime.get('runtime_kind') == 'GODOT_4_3_EXPORTED_PCK_LOADED_SOFTWARE_RENDER' and
         runtime.get('status') == 'PASS_PCK_LOADED_LOGIC_AND_RENDER' and
         runtime.get('pck_sha256') == MEMBERS['candidate.pck'][1] and
         runtime.get('source_sha') == SOURCE and runtime.get('request_id') == REQUEST and
         runtime.get('sale_ready') is False and runtime.get('physical_windows_gui') == 'DEFERRED_LOCAL_GATE' and
         runtime.get('identity_cas') in (None, 'HOLD_36_OWNER') and
         runtime.get('approved_package_version') is None and
         runtime.get('signed_product_msix') is None and
         runtime.get('store_submission_allowed') in (None, False) and
         runtime.get('japanese_font_glyphs_available') is True,
         'PCK runtime receipt does not bind new consumer artifact')
    required = {'first_30s_goal', 'bilingual_start_guide', 'clock_frozen_until_start', 'tower_order_1_2_3', 'next_tower_hud',
                'sentinel_telegraph_and_hit', 'time_and_warp_trap',
                'pause', 'win', 'timeout', 'restart', 'english_japanese',
                'board_visible_1024x768'}
    need(set(runtime.get('assertions', [])) == required,
         'missing or unexpected runtime assertions')
    bounds = runtime.get('board_colored_bounds')
    need(isinstance(bounds, dict) and
         all(type(bounds.get(k)) is int for k in ('left','right','top','bottom','width','height')) and
         bounds['width'] >= 420 and bounds['height'] >= 290 and
         bounds['left'] >= 120 and bounds['right'] <= 900 and
         bounds['top'] >= 165 and bounds['bottom'] <= 670 and
         bounds['width'] == bounds['right'] - bounds['left'] and
         bounds['height'] == bounds['bottom'] - bounds['top'],
         'BOARD_VISIBILITY_HOLD: real PCK board too small/clipped')
    screenshots = {}
    import struct
    import zlib
    for name in ('guide_en', 'guide_ja', 'initial', 'scan', 'trap', 'win', 'ja'):
        path = screenshot_dir / (name + '.png')
        need(path.is_file() and not path.is_symlink(), 'missing runtime screenshot: '+name)
        data = path.read_bytes()
        need(len(data) > 4096 and data[:16] == b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR',
             'invalid screenshot PNG: '+name)
        width, height, depth, color_type, comp, filt, interlace = struct.unpack('>IIBBBBB', data[16:29])
        need((width, height) == (1024, 768) and depth == 8 and
             color_type in (2, 6) and (comp, filt, interlace) == (0, 0, 0),
             'wrong screenshot PNG format/dimensions: '+name)
        pos, compressed, found_end = 8, bytearray(), False
        while pos < len(data):
            need(pos + 12 <= len(data), 'truncated PNG chunk')
            size = struct.unpack_from('>I', data, pos)[0]
            need(size <= 20_000_000 and pos + 12 + size <= len(data), 'unsafe PNG chunk')
            kind = data[pos+4:pos+8]
            chunk = data[pos+8:pos+8+size]
            crc = struct.unpack_from('>I', data, pos+8+size)[0]
            need(zlib.crc32(kind+chunk) & 0xffffffff == crc, 'PNG CRC mismatch')
            if kind == b'IDAT':
                compressed.extend(chunk)
            if kind == b'IEND':
                found_end = True
                need(pos + 12 + size == len(data), 'trailing PNG data')
                break
            pos += 12 + size
        need(found_end and compressed, 'incomplete PNG')
        raw = zlib.decompress(compressed)
        channels = 3 if color_type == 2 else 4
        need(len(raw) == height * (1 + width * channels) and
             len(set(raw)) > 12, 'blank or malformed software-rendered frame')
        screenshots[name] = {'sha256': sha(data), 'bytes': len(data),
                             'width': width, 'height': height}
    return {**preflight,
            'status': 'PCK_LOADED_SOFTWARE_RUNTIME_QA_PASS_NOT_HUMAN_GUI',
            'godot_pck_executed_this_run': True,
            'godot_4_3_runtime_assertions': sorted(required),
            'software_rendered_screenshots': screenshots,
            'board_colored_bounds': bounds,
            'physical_windows_gui': 'DEFERRED_LOCAL_GATE',
            'human_first_30s_readability': 'HOLD',
            'human_90s_gameplay': 'HOLD',
            'dpi_125_150': 'HOLD',
            'store_screenshot_quality': 'HOLD',
            'japanese_font_glyphs_available': runtime['japanese_font_glyphs_available'],
            'japanese_visual_quality': ('HOLD_PENDING_PHYSICAL_WINDOWS_REVIEW' if runtime['japanese_font_glyphs_available'] else 'HOLD_MISSING_JAPANESE_GLYPHS_IN_SOFTWARE_RENDER'),
            'identity_cas': 'HOLD_36_OWNER',
            'package_version': 'HOLD', 'signed_product_msix': 'HOLD',
            'windows_all_auto_intake': 'HOLD', 'sale_ready': False,
            'store_submission_allowed': False}

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--archive', type=Path)
    ap.add_argument('--extract-to', type=Path)
    ap.add_argument('--out', type=Path)
    ap.add_argument('--finalize', action='store_true')
    ap.add_argument('--preflight', type=Path)
    ap.add_argument('--runtime-json', type=Path)
    ap.add_argument('--screenshot-dir', type=Path)
    args = ap.parse_args(argv)
    try:
        if args.finalize:
            need(args.preflight is not None and args.runtime_json is not None and
                 args.screenshot_dir is not None, 'missing finalize input')
            preflight = json.loads(args.preflight.read_text(encoding='utf-8'), object_pairs_hook=unique_pairs)
            runtime = json.loads(args.runtime_json.read_text(encoding='utf-8'), object_pairs_hook=unique_pairs)
            result = finalize_runtime(preflight, runtime, args.screenshot_dir)
        else:
            need(args.archive is not None, 'missing archive')
            result = verify_archive(args.archive, extract_to=args.extract_to)
    except (OSError, ValueError, TypeError, zipfile.BadZipFile) as exc:
        result = {'status': 'BLOCKED_ARTIFACT_BYTES', 'reason': str(exc)[:200],
                  'sale_ready': False, 'store_submission_allowed': False}
        code = 2
    else:
        code = 0
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)+'\n'
    if args.out:
        args.out.write_text(payload, encoding='utf-8')
    print(payload, end='')
    return code

if __name__ == '__main__':
    raise SystemExit(main())
