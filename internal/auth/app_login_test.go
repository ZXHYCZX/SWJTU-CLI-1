package auth

import "testing"

func TestParseReAuthPage(t *testing.T) {
	body := []byte(`
		<script>
		var loginParams = {
			"service": "https:\/\/cas.swjtu.edu.cn\/authserver\/mobile\/callback?appId=1&login_type=mobileLogin",
			"reAuthType": "3",
			"isMultifactor": "true",
			"reAuthUserId": "2023000000"
		};
		</script>
		<span>短信已发送至 138****0000</span>
	`)
	p := parseReAuthPage("https://cas.swjtu.edu.cn/authserver/reAuthLoginView.do", body)
	if p.ReAuthType != "3" {
		t.Fatalf("reAuthType = %q", p.ReAuthType)
	}
	if p.IsMultifactor != "true" {
		t.Fatalf("isMultifactor = %q", p.IsMultifactor)
	}
	if p.UserID != "2023000000" {
		t.Fatalf("userId = %q", p.UserID)
	}
	if p.Service != "https://cas.swjtu.edu.cn/authserver/mobile/callback?appId=1&login_type=mobileLogin" {
		t.Fatalf("service = %q", p.Service)
	}
	if got := pPhone(body); got != "138****0000" {
		t.Fatalf("phone = %q", got)
	}
}

func TestMfaTypeLabel(t *testing.T) {
	cases := map[string]string{
		"3": "sms", "10": "otp", "4": "wecom", "11": "email", "99": "unknown",
	}
	for in, want := range cases {
		if got := mfaTypeLabel(in); got != want {
			t.Errorf("mfaTypeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMobileCodeFromURL(t *testing.T) {
	raw := "https://cas.swjtu.edu.cn/authserver/mobile/default.html#mobile_code=MxcguoRga7mCO2p1Ol2Jud40iqro2u03"
	if got := mobileCodeFromURL(raw); got != "MxcguoRga7mCO2p1Ol2Jud40iqro2u03" {
		t.Fatalf("got %q", got)
	}
	if got := mobileCodeFromURL("https://cas.swjtu.edu.cn/login"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestIsReAuthPage(t *testing.T) {
	if !isReAuthPage("https://cas.swjtu.edu.cn/authserver/reAuthLoginView.do", nil) {
		t.Fatal("reAuth URL should be detected")
	}
	if !isReAuthPage("https://cas.swjtu.edu.cn/authserver/login", []byte(`"isMultifactor":"true"`)) {
		t.Fatal("page body should be detected")
	}
	if isReAuthPage("https://cas.swjtu.edu.cn/authserver/login", []byte("normal login")) {
		t.Fatal("normal login page should not be detected")
	}
}
