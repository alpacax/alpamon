package shell

import "testing"

func TestUnwrapNestedPowerShell(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []string
		wantOk  bool
	}{
		{
			name:    "double-quoted argument in tail",
			command: `powershell -NoProfile -Command Write-Output "a|b"`,
			want:    []string{"powershell", "-NoProfile", "-Command", `Write-Output "a|b"`},
			wantOk:  true,
		},
		{
			name:    "pipe and quotes preserved verbatim in tail",
			command: `powershell.exe -Command Get-Service | Where-Object DisplayName -match "azure|batch|node"`,
			want:    []string{"powershell.exe", "-Command", `Get-Service | Where-Object DisplayName -match "azure|batch|node"`},
			wantOk:  true,
		},
		{
			name:    "case-insensitive exe and flag, exe form preserved, flag normalized",
			command: `PowerShell -command echo hi`,
			want:    []string{"PowerShell", "-Command", "echo hi"},
			wantOk:  true,
		},
		{
			name:    "pwsh executable",
			command: `pwsh -Command echo hi`,
			want:    []string{"pwsh", "-Command", "echo hi"},
			wantOk:  true,
		},
		{
			name:    "intermediate flag with value preserved",
			command: `powershell -ExecutionPolicy Bypass -Command echo hi`,
			want:    []string{"powershell", "-ExecutionPolicy", "Bypass", "-Command", "echo hi"},
			wantOk:  true,
		},
		{
			name:    "-c shorthand normalized to -Command",
			command: `powershell -c Write-Output "x"`,
			want:    []string{"powershell", "-Command", `Write-Output "x"`},
			wantOk:  true,
		},
		{
			name:    "minimal unambiguous abbreviation -com normalized to -Command",
			command: `powershell -com echo hi`,
			want:    []string{"powershell", "-Command", "echo hi"},
			wantOk:  true,
		},
		{
			name:    "ambiguous prefix -co rejected",
			command: `powershell -co echo hi`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "complex tail with pipe, braces, and quotes preserved verbatim",
			command: `powershell -NoProfile -Command Get-FileHash C:\Windows\notepad.exe | Format-Table @{N="Hash";E={$_.Hash.Substring(0,12)}},Path`,
			want:    []string{"powershell", "-NoProfile", "-Command", `Get-FileHash C:\Windows\notepad.exe | Format-Table @{N="Hash";E={$_.Hash.Substring(0,12)}},Path`},
			wantOk:  true,
		},
		{
			name:    "leading whitespace before executable",
			command: "  powershell -Command echo hi",
			want:    []string{"powershell", "-Command", "echo hi"},
			wantOk:  true,
		},
		{
			name:    "internal consecutive spaces in tail preserved, not collapsed",
			command: "powershell -Command echo  hi   there",
			want:    []string{"powershell", "-Command", "echo  hi   there"},
			wantOk:  true,
		},
		{
			name:    "not nested powershell",
			command: `Write-Output "a|b"`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "-File flag rejected",
			command: `powershell -File script.ps1`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "-EncodedCommand flag rejected",
			command: `powershell -EncodedCommand SQBuAHYA`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "-e shorthand for encoded command rejected",
			command: `powershell -e SQBuAHYA`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "-ec shorthand for encoded command rejected",
			command: `powershell -ec SQBuAHYA`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "executable alone with no arguments",
			command: `powershell`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "flags present but no -Command",
			command: `powershell -NoProfile`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "-Command with empty tail",
			command: `powershell -Command`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "-Command with stdin marker tail",
			command: `powershell -Command -`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "path-prefixed executable rejected",
			command: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command echo hi`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "quoted token before -Command aborts scan",
			command: `powershell -PSConsoleFile "a b.psc1" -Command echo hi`,
			want:    nil,
			wantOk:  false,
		},
		{
			name:    "empty string",
			command: "",
			want:    nil,
			wantOk:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := unwrapNestedPowerShell(tt.command)
			if ok != tt.wantOk {
				t.Fatalf("unwrapNestedPowerShell(%q) ok = %v, want %v", tt.command, ok, tt.wantOk)
			}
			if !ok {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("unwrapNestedPowerShell(%q) = %#v, want %#v", tt.command, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("unwrapNestedPowerShell(%q)[%d] = %q, want %q", tt.command, i, got[i], tt.want[i])
				}
			}
		})
	}
}
