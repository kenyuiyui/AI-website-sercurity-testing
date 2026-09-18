# PreToolUse hook: deny Write/Edit/NotebookEdit targets outside the allowed roots.
# Allowed roots: this project, ~/.claude, and %TEMP%\claude (Claude Code session scratchpads).
# Fails closed: anything unparseable or unresolvable is denied.
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Deny($reason) {
  @{ hookSpecificOutput = @{
      hookEventName = 'PreToolUse'
      permissionDecision = 'deny'
      permissionDecisionReason = $reason
  } } | ConvertTo-Json -Depth 5 -Compress
  exit 0
}

try {
  $reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), [System.Text.Encoding]::UTF8)
  $payload = $reader.ReadToEnd().TrimStart([char]0xFEFF) | ConvertFrom-Json
} catch {
  Deny "Blocked: path guard hook could not parse its input."
}

$target = $payload.tool_input.file_path
if (-not $target) { $target = $payload.tool_input.notebook_path }
if (-not $target) { Deny "Blocked: path guard hook found no target path." }

$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$roots = @(
  $projectRoot,
  (Join-Path $env:USERPROFILE '.claude'),
  (Join-Path $env:TEMP 'claude')
) | ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\') + '\' }

try { $full = [System.IO.Path]::GetFullPath($target) } catch { Deny "Blocked: cannot resolve path $target." }
foreach ($root in $roots) {
  if ($full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { exit 0 }
}

Deny "Blocked: $full is outside the allowed folders ($($roots -join ', '))."
