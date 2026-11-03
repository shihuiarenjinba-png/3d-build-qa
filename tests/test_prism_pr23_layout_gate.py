"""Negative fixtures for PR23 software layout; fixtures never prove real-PCK PASS."""
import copy
import unittest
from prism_pr23_layout_gate import (
    SOURCE, REQUEST, PCK_SHA, CAPTURE, LayoutHold, check_record,
)

def control(x,y,w,h,visible=True):
    return {"rect":{"x":x,"y":y,"width":w,"height":h},
            "minimum_width":0,"minimum_height":0,
            "inside_viewport":True,"visible":visible}

def label(x,y,w,h,visible=True,lines=1,text_width=250):
    c=control(x,y,w,h,visible)
    c.update({"font_size":21,"text":"sample","line_count":lines,
              "visible_line_count":lines,"text_width_unwrapped":text_width,
              "autowrap_mode":0})
    return c

def fixture():
    nodes={
        "guide":control(16,71,650,370),
        "title":label(40,110,600,36),
        "details":label(40,170,600,130,lines=4),
        "start":control(40,322,600,52),
        "guide_language":control(40,387,600,40),
        "top_hud":control(16,12,650,152,False),
        "bottom_hud":control(16,416,650,84,False),
        "status":label(18,20,648,26,False),
        "scan":label(18,60,648,24,False),
        "hint":label(18,430,648,50,False),
    }
    nodes["start"].update({"text":"Start Game (Enter)","disabled":False})
    nodes["guide_language"].update({"text":"日本語 (L)","disabled":False})
    active={
        "top_hud":control(16,12,650,152),
        "bottom_hud":control(16,416,650,84),
        "status":label(18,20,648,26,text_width=558),
        "scan":label(18,60,648,24,text_width=326),
        "hint":label(18,430,648,50,lines=2,text_width=800),
    }
    return {
        "schema_version":1,"source_sha":SOURCE,"request_id":REQUEST,
        "pck_sha256":PCK_SHA,"capture_kind":CAPTURE,
        "requested_window":"1024x720","simulated_dpi_percent":150,"locale":"en",
        "actual_image_width":960,"actual_image_height":720,
        "active_image_width":960,"active_image_height":720,
        "logical_viewport":{"x":0,"y":0,"width":682,"height":512},
        "content_scale_factor":1.5,"nodes":nodes,"active_nodes":active,
        "physical_windows_gui":"HOLD","human_first_30s":"HOLD",
        "human_real_time_90s":"HOLD","sale_ready":False,
        "store_submission_allowed":False,
    }

class LayoutNegativeFixtures(unittest.TestCase):
    def test_valid_shape_is_only_software(self):
        result=check_record(fixture(),"1024x720",150,"en")
        self.assertTrue(result["hud_hidden_before_start"])
    def test_old_pr22_source_rejected(self):
        r=fixture();r["source_sha"]="f4b458384243fdf379683ca793329614f61c9ead"
        with self.assertRaisesRegex(LayoutHold,"old PR22"):
            check_record(r,"1024x720",150,"en")
    def test_old_hud_peeking_rejected(self):
        r=fixture();r["nodes"]["top_hud"]["visible"]=True
        with self.assertRaisesRegex(LayoutHold,"peeks through"):
            check_record(r,"1024x720",150,"en")
    def test_start_offscreen_rejected(self):
        r=fixture();r["nodes"]["start"]["inside_viewport"]=False
        with self.assertRaisesRegex(LayoutHold,"clipped/invisible"):
            check_record(r,"1024x720",150,"en")
    def test_language_switch_missing_rejected(self):
        r=fixture();r["nodes"]["guide_language"]["visible"]=False
        with self.assertRaisesRegex(LayoutHold,"clipped/invisible"):
            check_record(r,"1024x720",150,"en")
    def test_false_physical_pass_rejected(self):
        r=fixture();r["physical_windows_gui"]="PASS"
        with self.assertRaisesRegex(LayoutHold,"physical"):
            check_record(r,"1024x720",150,"en")
    def test_guide_margin_regression_rejected(self):
        r=fixture();r["nodes"]["guide"]["rect"]["x"]=6
        with self.assertRaisesRegex(LayoutHold,"margin"):
            check_record(r,"1024x720",150,"en")
    def test_active_hud_not_restored_rejected(self):
        r=fixture();r["active_nodes"]["top_hud"]["visible"]=False
        with self.assertRaisesRegex(LayoutHold,"not restored"):
            check_record(r,"1024x720",150,"en")
    def test_text_line_clipping_rejected(self):
        r=fixture();r["nodes"]["details"]["visible_line_count"]=3
        with self.assertRaisesRegex(LayoutHold,"text clipped"):
            check_record(r,"1024x720",150,"en")
    def test_wrong_720_image_dimensions_rejected(self):
        r=fixture();r["actual_image_width"]=1024
        with self.assertRaisesRegex(LayoutHold,"image dimensions"):
            check_record(r,"1024x720",150,"en")

if __name__=="__main__":
    unittest.main()
