extends SceneTree
# Consumer-state headless smoke against the exact pinned Sentinel Godot source.
# This is NOT a human GUI, Windows DPI, or exported PCK execution test.
const LOGIC = preload("res://scripts/game_logic.gd")
const MAIN = preload("res://scripts/main.gd")

func check(ok: bool, why: String) -> void:
    if not ok:
        push_error("QA_90S_FAIL: " + why)
        assert(false, why)
        quit(1)

func _initialize() -> void:
    var scene = MAIN.new()
    scene.status_label = Label.new()
    scene.scan_label = Label.new()
    scene.hint_label = Label.new()
    scene.restart_button = Button.new()
    scene.pause_button = Button.new()
    scene.language_button = Button.new()
    for control in [scene.status_label, scene.scan_label, scene.hint_label, scene.restart_button, scene.pause_button, scene.language_button]:
        scene.add_child(control)
    var g = scene.game
    check(g.remaining == 90.0 and g.next_target == 0 and g.status == "playing", "90-second fresh run")
    scene._refresh_ui()
    check(scene.status_label.text.contains("Towers 0/3") and scene.status_label.text.contains("90s left"), "first-frame goal progress and time")
    check(scene.hint_label.text.contains("Activate towers in order"), "first-frame English objective")
    check(scene.scan_label.text.contains("warning") and scene.scan_label.text.contains("fires in"), "first-frame Sentinel telegraph")
    check(scene.restart_button.text.contains("Restart") and scene.pause_button.text.contains("Pause"), "first-frame recovery controls")

    # First 30 seconds: a warning must precede damage and an explicit reason must appear.
    check(g.move(Vector2i(0, -1)), "step into north scan lane")
    g.tick(3.9)
    check(g.scan_hits == 0 and not g.scan_active(), "warning is non-damaging")
    g.tick(0.2)
    scene._refresh_ui()
    check(g.scan_hits == 1 and g.last_event == "sentinel_scan" and g.player == LOGIC.START_CELL, "predictable six-second scan knockback")
    check(scene.hint_label.text.contains("Lost 6 seconds") and scene.scan_label.text.contains("SCAN ends"), "visible English scan failure reason")
    g.reset()
    g.tick(29.9)
    scene._refresh_ui()
    check(g.status == "playing" and g.remaining > 60.0 and g.remaining < 60.2, "29.9s clock progression")
    check(scene.status_label.text.contains("61s left"), "remaining seconds readable at 30-second mark")

    # Time trap, warp trap and the explanation visible after each event.
    g.reset()
    check(g.move(Vector2i(0, -1)) and g.move(Vector2i(0, -1)), "reach orange time trap")
    scene._refresh_ui()
    check(g.remaining == 75.0 and g.trap_hits == 1 and scene.hint_label.text.contains("Lost 15 seconds"), "time trap explains penalty")
    g.reset()
    check(g.move(Vector2i(-1, 0)) and g.move(Vector2i(-1, 0)), "reach purple warp trap")
    scene._refresh_ui()
    check(g.player == LOGIC.START_CELL and g.remaining == 82.0 and scene.hint_label.text.contains("Lost 8 seconds"), "warp explains reset and penalty")

    # Pause, restart, tower order, completion, failure, language.
    g.toggle_pause()
    var frozen = g.remaining
    g.tick(12.0)
    scene._refresh_ui()
    check(g.remaining == frozen and scene.hint_label.text.begins_with("Paused."), "pause and reason")
    scene._restart()
    check(g.remaining == 90.0 and g.trap_hits == 0 and g.scan_hits == 0, "restart clears penalties")
    check(g.move(Vector2i(0, -1)) and g.move(Vector2i(0, -1)), "approach first tower")
    check(g.move(Vector2i(-1, 0)) and g.move(Vector2i(-1, 0)) and g.next_target == 1, "tower one order")
    for i in range(4):
        check(g.move(Vector2i(1, 0)), "top-row route")
    check(g.next_target == 2, "tower two order")
    for i in range(4):
        check(g.move(Vector2i(0, 1)), "right-edge route")
    scene._refresh_ui()
    check(g.status == "won" and g.next_target == 3 and scene.hint_label.text.contains("Route complete!"), "completion and replay invitation")
    scene._restart()
    g.tick(91.0)
    scene._refresh_ui()
    check(g.status == "failed" and scene.hint_label.text.contains("Time up."), "timeout reason")
    scene._toggle_language()
    scene._refresh_ui()
    check(scene.hint_label.text.contains("時間切れ") and scene.restart_button.text.contains("再スタート"), "Japanese timeout and replay")
    scene._restart()
    scene._refresh_ui()
    check(scene.hint_label.text.contains("塔を順番に起動") and scene.scan_label.text.contains("予告"), "Japanese first-run objective and scan warning")
    scene.free()
    print("PASS: QA_90S_SENTINEL_SOURCE_RUNTIME_EN_JA_GOAL_TELEGRAPH_TRAPS_PAUSE_WIN_FAIL_RETRY")
    quit(0)
