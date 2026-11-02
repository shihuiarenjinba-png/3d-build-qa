extends SceneTree
# Execute compiled scripts/scenes from the exact SHA-pinned exported PCK.
# This is Mesa/Xvfb software rendering, NOT physical Windows GUI evidence.
const SOURCE = "dc2235a481b50ffe77a20c07bc7fdf46b023236e"
const REQUEST = "3d-prism-route-3d-dc2235a481b5"
const PCK_SHA = "92d4a653bc27dc1da358c0a03161f5f701d5f14f57f8fcb6353b43ea19fdebd9"

func check(ok: bool, why: String) -> void:
    if not ok:
        push_error("PCK_RUNTIME_FAIL: " + why)
        assert(false, why)
        quit(2)

func _initialize() -> void:
    call_deferred("_run")

func _screenshot(name: String) -> void:
    await RenderingServer.frame_post_draw
    var image: Image = get_root().get_texture().get_image()
    check(image != null and image.get_width() == 1024 and image.get_height() == 768, "software-rendered 1024x768 frame " + name)
    var path: String = OS.get_environment("PRISM_SCREENSHOT_DIR").path_join(name + ".png")
    check(image.save_png(path) == OK, "save real PCK-rendered screenshot " + name)

func _run() -> void:
    check(OS.get_environment("PRISM_EXPECTED_PCK_SHA") == PCK_SHA, "PCK SHA not preverified by byte gate")
    check(OS.get_environment("PRISM_SCREENSHOT_DIR") != "", "missing screenshot directory")
    check(OS.get_environment("PRISM_RUNTIME_RECEIPT") != "", "missing runtime receipt path")
    var packed = load("res://scenes/main.tscn")
    check(packed is PackedScene, "main scene missing from actual exported PCK")
    var scene = packed.instantiate()
    get_root().add_child(scene)
    await process_frame
    await process_frame
    var game = scene.get("game")
    check(game != null and game.remaining > 89.0 and game.remaining <= 90.0, "first frame 90s clock")
    check(scene.get("tower_order_labels").size() == 3, "three numbered world-space towers")
    for i in range(3):
        var marker = scene.get("tower_order_labels")[i]
        check(marker is Label3D and marker.text == str(i + 1) and marker.visible, "world-space tower number " + str(i + 1))
    check(scene.get("status_label").text.contains("NEXT Tower 1"), "first-frame next-tower HUD")
    check(scene.get("hint_label").text.contains("1→2→3"), "first-frame ordered goal")
    check(scene.get("scan_label").text.contains("warning"), "first-frame Sentinel warning")
    check(scene.get("scan_markers").size() > 0, "real scan lane geometry")
    await _screenshot("initial")

    # Virtual first 30 seconds: warning precedes hit and penalty reason is visible.
    game.reset()
    check(game.move(Vector2i(0, -1)), "enter warned lane")
    game.tick(3.9)
    check(game.scan_hits == 0 and not game.scan_active(), "warning before scan hit")
    game.tick(0.2)
    scene.call("_sync_world")
    scene.call("_sync_scan_world")
    scene.call("_refresh_ui")
    check(game.scan_hits == 1 and scene.get("hint_label").text.contains("Lost 6 seconds"), "visible scan penalty")
    await _screenshot("scan")
    game.reset()
    game.tick(29.9)
    scene.call("_refresh_ui")
    check(game.status == "playing" and game.remaining > 59.0 and game.remaining < 61.0, "29.9s game state")

    game.reset()
    check(game.move(Vector2i(0, -1)) and game.move(Vector2i(0, -1)), "time trap route")
    scene.call("_sync_world")
    scene.call("_refresh_ui")
    check(game.remaining == 75.0 and scene.get("hint_label").text.contains("Lost 15 seconds"), "time trap reason")
    await _screenshot("trap")
    game.reset()
    check(game.move(Vector2i(-1, 0)) and game.move(Vector2i(-1, 0)), "warp trap route")
    scene.call("_refresh_ui")
    check(game.remaining == 82.0 and scene.get("hint_label").text.contains("Lost 8 seconds"), "warp trap reason")

    game.reset()
    game.toggle_pause()
    var paused_time: float = game.remaining
    game.tick(10.0)
    scene.call("_refresh_ui")
    check(game.remaining == paused_time and scene.get("hint_label").text.contains("Paused."), "pause freezes timer")
    game.reset()
    check(game.move(Vector2i(0, -1)) and game.move(Vector2i(0, -1)), "approach tower one")
    check(game.move(Vector2i(-1, 0)) and game.move(Vector2i(-1, 0)), "activate tower one")
    scene.call("_refresh_ui")
    check(game.next_target == 1 and scene.get("status_label").text.contains("NEXT Tower 2"), "next tower changes to 2")
    for i in range(4):
        check(game.move(Vector2i(1, 0)), "reach tower two")
    scene.call("_refresh_ui")
    check(game.next_target == 2 and scene.get("status_label").text.contains("NEXT Tower 3"), "next tower changes to 3")
    for i in range(4):
        check(game.move(Vector2i(0, 1)), "reach tower three")
    scene.call("_sync_world")
    scene.call("_refresh_ui")
    check(game.status == "won" and scene.get("hint_label").text.contains("Route complete!"), "win and replay invitation")
    await _screenshot("win")
    scene.call("_restart")
    check(game.status == "playing" and game.remaining > 89.0 and game.next_target == 0, "restart after win")
    game.tick(90.1)
    scene.call("_refresh_ui")
    check(game.status == "failed" and scene.get("hint_label").text.contains("Time up."), "90s timeout and failure reason")
    scene.call("_toggle_language")
    scene.call("_refresh_ui")
    check(scene.get("status_label").text.contains("次の塔") and scene.get("hint_label").text.contains("時間切れ"), "Japanese failure and goal")
    scene.call("_restart")
    check(game.status == "playing" and scene.get("hint_label").text.contains("1→2→3"), "Japanese retry instructions")
    await _screenshot("ja")
    var japanese_font: Font = scene.get("language_button").get_theme_font("font")
    var japanese_glyphs_available: bool = japanese_font != null and japanese_font.has_char(0x65E5) and japanese_font.has_char(0x672C) and japanese_font.has_char(0x8A9E)
    check(japanese_glyphs_available, "embedded Japanese glyphs must render from actual PCK")

    var assertions = ["first_30s_goal", "tower_order_1_2_3", "next_tower_hud", "sentinel_telegraph_and_hit", "time_and_warp_trap", "pause", "win", "timeout", "restart", "english_japanese"]
    var receipt = {"schema_version": 1, "runtime_kind": "GODOT_4_3_EXPORTED_PCK_LOADED_SOFTWARE_RENDER", "status": "PASS_PCK_LOADED_LOGIC_AND_RENDER", "source_sha": SOURCE, "request_id": REQUEST, "pck_sha256": PCK_SHA, "assertions": assertions, "physical_windows_gui": "DEFERRED_LOCAL_GATE", "japanese_font_glyphs_available": japanese_glyphs_available, "sale_ready": false}
    var file = FileAccess.open(OS.get_environment("PRISM_RUNTIME_RECEIPT"), FileAccess.WRITE)
    check(file != null, "cannot write PCK runtime receipt")
    file.store_string(JSON.stringify(receipt, "  ") + "\n")
    file.close()
    print("PASS: PRISM_CONSUMER_REAL_PCK_SOFTWARE_RUNTIME_90S_STATES_AND_4_SCREENSHOTS_NOT_HUMAN_GUI")
    scene.queue_free()
    quit(0)
