extends SceneTree
# PR22 ONLY: load actual compiled Factory PCK in Godot 4.3 Mesa/Xvfb.
# Virtual time advances are deterministic software tests, NOT human real-time 90s.
const SOURCE = "f4b458384243fdf379683ca793329614f61c9ead"
const REQUEST = "3d-prism-route-3d-f4b458384243"
const PCK_SHA = "d1363805e4f899b0a895b6c4153f3fc902d548529c0cc47579b965666fcd98ec"

const EXPECTED = {
    "timeout_en": "Time up. Reach towers 1→2→3 faster; retry.",
    "timeout_ja": "時間切れ。塔1→2→3の順に急いで再挑戦。",
    "trap_en": "Trap drained the clock. Avoid orange/purple tiles; retry.",
    "trap_ja": "罠で時間切れ。橙・紫のマスを避けて再挑戦。",
    "sentinel_en": "Sentinel scan ended the run. Avoid the warning lane; retry.",
    "sentinel_ja": "Sentinel照射で時間切れ。予告帯を避けて再挑戦。"
}
var states: Dictionary = {}

func check(ok: bool, reason: String) -> void:
    if not ok:
        push_error("PR22_PCK_RUNTIME_FAIL: " + reason)
        quit(2)
        assert(false, reason)

func _initialize() -> void:
    call_deferred("_run")

func _screenshot(name: String) -> void:
    await RenderingServer.frame_post_draw
    var img: Image = get_root().get_texture().get_image()
    check(img != null and img.get_width() == 1024 and img.get_height() == 768,
          "must render real 1024x768 PCK frame " + name)
    var path: String = OS.get_environment("PRISM_SCREENSHOT_DIR").path_join(name + ".png")
    check(img.save_png(path) == OK, "cannot save " + name)

func _record(scene: Node, game, name: String, reason: String) -> void:
    var language: String = name.substr(name.length() - 2, 2)
    check(scene.get("language") == language, "wrong language: " + name)
    scene.call("_refresh_ui")
    var hint: String = scene.get("hint_label").text
    if reason != "":
        check(game.status == "failed" and game.failure_reason == reason,
              "wrong final cause: " + name)
        check(hint == EXPECTED[name], "incorrect bilingual cause-specific advice: " + name)
    else:
        check(game.status == "playing" and game.failure_reason == ""
              and game.next_target == 0 and game.remaining > 89.0,
              "retry did not reset state: " + name)
        check(hint.contains("1→2→3"), "retry must show tower order: " + name)
    states[name] = {
        "status": game.status, "failure_reason": game.failure_reason,
        "language": language, "hint_text": hint,
        "remaining_seconds": int(ceil(game.remaining)),
        "next_target": game.next_target
    }
    await _screenshot(name)

func _record_pair(scene: Node, game, cause: String) -> void:
    check(scene.get("language") == "en", "English expected at start of pair")
    await _record(scene, game, cause + "_en", cause if cause != "retry" else "")
    scene.call("_toggle_language")
    await _record(scene, game, cause + "_ja", cause if cause != "retry" else "")
    scene.call("_toggle_language")
    check(scene.get("language") == "en", "locale must return to English")

func _run() -> void:
    check(OS.get_environment("PRISM_EXPECTED_PCK_SHA") == PCK_SHA,
          "compiled PCK not independently SHA-verified")
    check(OS.get_environment("PRISM_SCREENSHOT_DIR") != ""
          and OS.get_environment("PRISM_RUNTIME_RECEIPT") != "",
          "missing CI evidence paths")
    var packed = load("res://scenes/main.tscn")
    check(packed is PackedScene, "cannot load scene from compiled PR22 PCK")
    var scene = packed.instantiate()
    get_root().add_child(scene)
    await process_frame
    await process_frame
    var game = scene.get("game")
    check(game != null and scene.get("onboarding_active") and game.remaining == 90.0,
          "compiled scene must start with 90s clock frozen")
    if scene.get("language") == "ja":
        scene.call("_toggle_language")
    check(scene.get("language") == "en", "English start")
    scene.call("_start_run")
    check(not scene.get("onboarding_active"), "Start must dismiss guide")
    # No trap contact: a pure 90s timeout must NEVER suggest avoiding traps.
    game.reset()
    game.tick(90.1)
    check(game.status == "failed" and game.failure_reason == "timeout"
          and game.trap_hits == 0 and game.scan_hits == 0, "natural timeout cause")
    await _record_pair(scene, game, "timeout")

    # A previous trap event is stale. Time expiring later must still be TIMEOUT.
    scene.call("_restart")
    check(game.move(Vector2i(0, -1)) and game.move(Vector2i(0, -1)),
          "enter time trap for stale-event negative")
    check(game.last_event == "time_trap" and game.status == "playing",
          "stale trap event setup")
    game.tick(75.1)
    scene.call("_refresh_ui")
    check(game.status == "failed" and game.failure_reason == "timeout"
          and scene.get("hint_label").text == EXPECTED["timeout_en"],
          "stale trap event falsely relabelled TIMEOUT")

    # TRAP: first spend 76s safely in center, then enter a -15s trap with 14s left.
    scene.call("_restart")
    game.tick(76.0)
    check(game.status == "playing" and game.remaining > 13.9
          and game.remaining < 14.1, "trap setup clock")
    check(game.move(Vector2i(0, -1)) and game.move(Vector2i(0, -1)),
          "enter trap through legal movement")
    check(game.status == "failed" and game.failure_reason == "trap"
          and game.trap_hits == 1, "natural trap exhaustion")
    await _record_pair(scene, game, "trap")

    # SENTINEL: scan phase 87.9s is a south-lane warning; entering south lane
    # and crossing the 88s active threshold incurs a natural 6s fatal hit.
    scene.call("_restart")
    game.tick(87.9)
    check(game.status == "playing" and game.remaining > 2.0
          and game.scan_direction() == 2 and not game.scan_active(),
          "Sentinel warning phase")
    check(game.move(Vector2i(0, 1)), "enter warned south scan lane")
    game.tick(0.2)
    check(game.status == "failed" and game.failure_reason == "sentinel"
          and game.scan_hits == 1, "natural Sentinel exhaustion")
    scene.call("_sync_world")
    scene.call("_sync_scan_world")
    await _record_pair(scene, game, "sentinel")

    # Restart after failure must clear reason, restore tower 1 and full clock.
    scene.call("_restart")
    check(game.status == "playing" and game.failure_reason == ""
          and game.remaining == 90.0 and game.next_target == 0
          and game.trap_hits == 0 and game.scan_hits == 0, "retry reset")
    await _record_pair(scene, game, "retry")
    var receipt = {
        "schema_version": 1, "runtime_kind": "GODOT_4_3_PR22_EXPORTED_PCK_SOFTWARE_RENDER",
        "status": "PASS_PCK_CAUSE_SPECIFIC_STATES",
        "capture_kind": "GODOT_MESA_XVFB_TIME_ADVANCED_NOT_HUMAN",
        "source_sha": SOURCE, "request_id": REQUEST, "pck_sha256": PCK_SHA,
        "states": states, "stale_trap_event_timeout_checked": true,
        "physical_windows_gui": "HOLD", "human_real_time_90s": "HOLD",
        "sale_ready": false, "store_submission_allowed": false
    }
    var file = FileAccess.open(OS.get_environment("PRISM_RUNTIME_RECEIPT"), FileAccess.WRITE)
    check(file != null, "cannot write runtime receipt")
    file.store_string(JSON.stringify(receipt, "  ") + "\n")
    file.close()
    print("PASS: PR22_REAL_EXPORTED_PCK_8_BILINGUAL_CAUSE_AND_RETRY_FRAMES_NOT_PHYSICAL")
    scene.queue_free()
    quit(0)
