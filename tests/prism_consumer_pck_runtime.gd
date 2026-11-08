extends SceneTree
# Execute compiled scripts/scenes from the exact SHA-pinned exported PCK.
# This is Mesa/Xvfb software rendering, NOT physical Windows GUI evidence.
const SOURCE = "e8c77192a06527b005168359433f2868ff86708e"
const REQUEST = "3d-prism-route-3d-e8c77192a065"
const PCK_SHA = "c4f36ed505dc447a5977d9cd5e1ed68d78d089d8b502184647acf44370261630"

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

func _board_bounds() -> Dictionary:
    # Quantify colored board geometry in an actual PCK frame, excluding HUD.
    # This is not a human legibility test.
    await RenderingServer.frame_post_draw
    var image: Image = get_root().get_texture().get_image()
    var left: int = 1024
    var right: int = 0
    var top: int = 768
    var bottom: int = 0
    for y in range(170, 660, 2):
        for x in range(0, 1024, 2):
            var c: Color = image.get_pixel(x, y)
            var spread: float = max(c.r, max(c.g, c.b)) - min(c.r, min(c.g, c.b))
            if spread > 0.07 and c.r + c.g + c.b > 0.3:
                left = min(left, x)
                right = max(right, x)
                top = min(top, y)
                bottom = max(bottom, y)
    check(right > left and bottom > top, "visible 3D board geometry")
    return {"left": left, "right": right, "top": top, "bottom": bottom,
            "width": right - left, "height": bottom - top}

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
    check(game != null and game.remaining == 90.0 and scene.get("onboarding_active"), "first-run guide holds the full 90s clock")
    check(scene.get("onboarding_title").text.contains("1 → 2 → 3"), "English first-run tower goal visible")
    check(scene.get("onboarding_details").text.contains("WASD") and scene.get("onboarding_details").text.contains("YELLOW") and scene.get("onboarding_details").text.contains("RED") and scene.get("onboarding_details").text.contains("ORANGE") and scene.get("onboarding_details").text.contains("PURPLE") and scene.get("onboarding_details").text.contains("90-second") and scene.get("onboarding_details").text.count("\n") == 3, "English four-line first-run guide explains movement, warning, traps, timer")
    var guide_style = scene.get("onboarding_panel").get_theme_stylebox("panel") as StyleBoxFlat
    check(guide_style != null and guide_style.bg_color.a >= 0.95 and guide_style.bg_color.r < 0.2, "guide is opaque and not transparent over gameplay")
    var start_style = scene.get("start_button").get_theme_stylebox("normal") as StyleBoxFlat
    check(start_style != null and start_style.bg_color.g > 0.4, "Start button is visually emphasized")
    await _screenshot("guide_en")
    scene.call("_toggle_language")
    check(scene.get("onboarding_title").text.contains("1 → 2 → 3") and scene.get("onboarding_details").text.contains("WASD") and scene.get("onboarding_details").text.contains("黄色") and scene.get("onboarding_details").text.contains("赤") and scene.get("onboarding_details").text.contains("橙") and scene.get("onboarding_details").text.contains("紫") and scene.get("onboarding_details").text.contains("90秒") and scene.get("onboarding_details").text.count("\n") == 3, "Japanese four-line first-run guide explains movement, warning, traps, timer")
    await _screenshot("guide_ja")
    scene.call("_toggle_language")
    var guide_remaining: float = game.remaining
    scene.call("_process", 30.0)
    check(game.remaining == guide_remaining and game.scan_elapsed == 0.0, "30s reading time never consumes game clock or scan")
    scene.call("_start_run")
    check(not scene.get("onboarding_active") and not scene.get("onboarding_panel").visible, "Start dismisses first-run guide")
    check(game.remaining > 89.0 and game.remaining <= 90.0, "90s clock starts after Start")
    check(scene.get("tower_order_labels").size() == 3, "three numbered world-space towers")
    for i in range(3):
        var marker = scene.get("tower_order_labels")[i]
        check(marker is Label3D and marker.text == str(i + 1) and marker.visible, "world-space tower number " + str(i + 1))
    # Inspect UI theme on the actual loaded PCK, not a source-level fixture.
    var status = scene.get("status_label") as Label
    var scan = scene.get("scan_label") as Label
    var hint = scene.get("hint_label") as Label
    var restart = scene.get("restart_button") as Button
    check(status.get_theme_font_size("font_size") >= 22 and scan.get_theme_font_size("font_size") >= 19 and hint.get_theme_font_size("font_size") >= 20 and restart.get_theme_font_size("font_size") >= 19,
          "actual compiled HUD font sizes satisfy consumer legibility floor")
    var top_panel = status.get_parent().get_parent() as PanelContainer
    var bottom_panel = hint.get_parent() as PanelContainer
    var top_style = top_panel.get_theme_stylebox("panel") as StyleBoxFlat
    var bottom_style = bottom_panel.get_theme_stylebox("panel") as StyleBoxFlat
    var hud_text = status.get_theme_color("font_color")
    check(top_style != null and bottom_style != null and top_style.bg_color.a >= 0.95 and bottom_style.bg_color.a >= 0.95,
          "actual compiled HUD has opaque high-contrast panels")
    check(hud_text.get_luminance() - top_style.bg_color.get_luminance() >= 0.70 and hint.get_theme_color("font_color").get_luminance() - bottom_style.bg_color.get_luminance() >= 0.70,
          "actual compiled HUD contrast above readability floor")
    check(scene.get("status_label").text.contains("NEXT Tower 1"), "first-frame next-tower HUD")
    check(scene.get("hint_label").text.contains("1→2→3"), "first-frame ordered goal")
    await process_frame
    print("PCK_HINT_LAYOUT_DIAGNOSTIC: text=", JSON.stringify(hint.text), " lines=", hint.get_line_count(), " size=", hint.size, " parent_size=", hint.get_parent().size, " font_size=", hint.get_theme_font_size("font_size"))
    check(hint.get_line_count() == 1, "English gameplay hint must fit one line in actual 1024x768 PCK")
    check(scene.get("scan_label").text.contains("warning"), "first-frame Sentinel warning")
    check(scene.get("scan_markers").size() > 0, "real scan lane geometry")
    await _screenshot("initial")
    var board_bounds: Dictionary = await _board_bounds()
    check(board_bounds["width"] >= 420 and board_bounds["height"] >= 290,
          "consumer board is visible at 1024x768")
    check(board_bounds["top"] >= 165 and board_bounds["bottom"] <= 670,
          "board must not overlap HUD")
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
    check(game.status == "failed" and game.remaining <= 0.0, "actual timeout state before defeat frame")
    check(scene.get("status_label").text.contains("次の塔") and scene.get("hint_label").text.contains("時間切れ"), "Japanese failure and goal")
    await _screenshot("timeout_ja")
    scene.call("_restart")
    check(game.status == "playing" and game.remaining > 89.0 and game.next_target == 0, "post-defeat retry resets full timer and tower")
    check(scene.get("hint_label").text.contains("1→2→3"), "Japanese retry instructions")
    check(hint.get_line_count() == 1, "Japanese gameplay hint must fit one line in actual 1024x768 PCK")
    await _screenshot("retry_ja")
    # Keep the original seventh JA baseline frame distinct from the new retry
    # frame without changing the compiled PCK or simulating a human 90s play.
    game.tick(0.6)
    scene.call("_refresh_ui")
    check(game.status == "playing" and game.remaining < 90.0, "JA baseline after retry advances")
    await _screenshot("ja")
    var japanese_font: Font = scene.get("language_button").get_theme_font("font")
    var japanese_glyphs_available: bool = japanese_font != null and japanese_font.has_char(0x65E5) and japanese_font.has_char(0x672C) and japanese_font.has_char(0x8A9E)
    check(japanese_glyphs_available, "embedded Japanese glyphs must render from actual PCK")

    var assertions = ["first_30s_goal", "bilingual_start_guide", "clock_frozen_until_start", "tower_order_1_2_3", "next_tower_hud", "sentinel_telegraph_and_hit", "time_and_warp_trap", "pause", "win", "timeout", "restart", "english_japanese", "board_visible_1024x768", "hud_contrast_and_type", "bilingual_hint_single_line_1024"]
    var receipt = {"schema_version": 1, "runtime_kind": "GODOT_4_3_EXPORTED_PCK_LOADED_SOFTWARE_RENDER", "status": "PASS_PCK_LOADED_LOGIC_AND_RENDER", "source_sha": SOURCE, "request_id": REQUEST, "pck_sha256": PCK_SHA, "assertions": assertions, "board_colored_bounds": board_bounds, "physical_windows_gui": "DEFERRED_LOCAL_GATE", "japanese_font_glyphs_available": japanese_glyphs_available, "timeout_retry_states": {"capture_kind": "GODOT_4_3_SOFTWARE_RENDER_TIME_ADVANCED_NOT_HUMAN", "timeout_status": "failed", "timeout_language": "ja", "timeout_reason": "時間切れ", "timeout_remaining_seconds": 0, "retry_status": "playing", "retry_language": "ja", "retry_next_target": 0, "retry_remaining_seconds": 90, "frame_names": ["timeout_ja", "retry_ja"]}, "sale_ready": false}
    var file = FileAccess.open(OS.get_environment("PRISM_RUNTIME_RECEIPT"), FileAccess.WRITE)
    check(file != null, "cannot write PCK runtime receipt")
    file.store_string(JSON.stringify(receipt, "  ") + "\n")
    file.close()
    print("PASS: PRISM_CONSUMER_REAL_PCK_FIRST30S_90S_STATES_7_SCREENSHOTS_NOT_HUMAN_GUI")
    scene.queue_free()
    quit(0)
