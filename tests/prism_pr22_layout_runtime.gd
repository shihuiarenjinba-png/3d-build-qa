extends SceneTree
# Read-only cloud layout probe of the exact Factory PR22 compiled PCK.
# The scale factor models UI scaling only; it is NOT a physical Windows DPI test.
const SOURCE = "f4b458384243fdf379683ca793329614f61c9ead"
const REQUEST = "3d-prism-route-3d-f4b458384243"
const PCK_SHA = "d1363805e4f899b0a895b6c4153f3fc902d548529c0cc47579b965666fcd98ec"

func fail(reason: String) -> void:
    push_error("PR22_LAYOUT_CAPTURE_FAIL: " + reason)
    quit(2)
    assert(false, reason)

func rect_dict(r: Rect2) -> Dictionary:
    return {"x": r.position.x, "y": r.position.y,
            "width": r.size.x, "height": r.size.y}

func control_dict(control: Control, viewport: Rect2) -> Dictionary:
    var r: Rect2 = control.get_global_rect()
    var epsilon := 1.5
    return {
        "rect": rect_dict(r),
        "minimum_width": control.get_combined_minimum_size().x,
        "minimum_height": control.get_combined_minimum_size().y,
        "inside_viewport": r.position.x >= viewport.position.x - epsilon
            and r.position.y >= viewport.position.y - epsilon
            and r.end.x <= viewport.end.x + epsilon
            and r.end.y <= viewport.end.y + epsilon,
        "visible": control.is_visible_in_tree()
    }

func label_dict(label: Label, viewport: Rect2) -> Dictionary:
    var d := control_dict(label, viewport)
    var font: Font = label.get_theme_font("font")
    var font_size: int = label.get_theme_font_size("font_size")
    d["font_size"] = font_size
    d["text"] = label.text
    d["line_count"] = label.get_line_count()
    d["visible_line_count"] = label.get_visible_line_count()
    d["text_width_unwrapped"] = font.get_string_size(
        label.text, HORIZONTAL_ALIGNMENT_LEFT, -1, font_size).x
    d["autowrap_mode"] = label.autowrap_mode
    return d

func _initialize() -> void:
    call_deferred("_run")

func _run() -> void:
    if OS.get_environment("PRISM_EXPECTED_PCK_SHA") != PCK_SHA:
        fail("exact PCK SHA preflight absent")
    var locale: String = OS.get_environment("PRISM_LAYOUT_LOCALE")
    var dpi: int = int(OS.get_environment("PRISM_LAYOUT_DPI"))
    var physical_size: String = OS.get_environment("PRISM_LAYOUT_SIZE")
    var output: String = OS.get_environment("PRISM_LAYOUT_OUTPUT")
    if not (locale in ["ja", "en"] and dpi in [100, 125, 150]
            and physical_size in ["1024x720", "1024x768"] and output != ""):
        fail("invalid layout scenario")
    get_root().content_scale_factor = float(dpi) / 100.0
    var packed = load("res://scenes/main.tscn")
    if not (packed is PackedScene):
        fail("PR22 compiled scene unavailable")
    var scene: Node = packed.instantiate()
    get_root().add_child(scene)
    await process_frame
    await process_frame
    if scene.get("language") != locale:
        scene.call("_toggle_language")
    await process_frame
    await process_frame
    var viewport: Rect2 = get_root().get_visible_rect()
    var panel: Control = scene.get("onboarding_panel")
    var title: Label = scene.get("onboarding_title")
    var details: Label = scene.get("onboarding_details")
    var start: Button = scene.get("start_button")
    var status: Label = scene.get("status_label")
    var scan: Label = scene.get("scan_label")
    var hint: Label = scene.get("hint_label")
    var top: Control = status.get_parent().get_parent()
    var bottom: Control = hint.get_parent()
    if not (panel.is_visible_in_tree() and start.is_visible_in_tree()
            and scene.get("onboarding_active") and scene.get("game").remaining == 90.0):
        fail("first-run guide / frozen clock not present")
    var nodes := {
        "guide": control_dict(panel, viewport),
        "title": label_dict(title, viewport),
        "details": label_dict(details, viewport),
        "start": control_dict(start, viewport),
        "top_hud": control_dict(top, viewport),
        "status": label_dict(status, viewport),
        "scan": label_dict(scan, viewport),
        "bottom_hud": control_dict(bottom, viewport),
        "hint": label_dict(hint, viewport)
    }
    nodes["start"]["text"] = start.text
    nodes["start"]["disabled"] = start.disabled
    var screenshot_path: String = output.get_basename() + ".png"
    await RenderingServer.frame_post_draw
    var image: Image = get_root().get_texture().get_image()
    if image == null or image.save_png(screenshot_path) != OK:
        fail("screenshot save failed")
    var receipt := {
        "schema_version": 1,
        "source_sha": SOURCE, "request_id": REQUEST, "pck_sha256": PCK_SHA,
        "capture_kind": "GODOT_4_3_MESA_XVFB_PR22_SOFTWARE_LAYOUT_ONLY",
        "locale": locale, "simulated_dpi_percent": dpi,
        "requested_window": physical_size,
        "actual_image_width": image.get_width(),
        "actual_image_height": image.get_height(),
        "logical_viewport": rect_dict(viewport),
        "content_scale_factor": get_root().content_scale_factor,
        "nodes": nodes,
        "physical_windows_gui": "HOLD", "human_first_30s": "HOLD",
        "human_real_time_90s": "HOLD", "sale_ready": false,
        "store_submission_allowed": false
    }
    var file = FileAccess.open(output, FileAccess.WRITE)
    if file == null:
        fail("receipt output failed")
    file.store_string(JSON.stringify(receipt, "  ") + "\n")
    file.close()
    print("CAPTURED: PR22_SOFTWARE_LAYOUT_" + physical_size + "_" + str(dpi) + "_" + locale + "_NOT_PHYSICAL")
    scene.queue_free()
    quit(0)
