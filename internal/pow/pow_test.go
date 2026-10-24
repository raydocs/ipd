package pow

import "testing"

func TestSolveAndReject(t *testing.T) {
	ch := Issue(8)
	token := Solve(ch)
	if token == "" || !Verify(token) {
		t.Fatal(token)
	}
	if Verify("nope") || Verify(ch+":not-a-solution") {
		t.Fatal("accepted junk")
	}
}
