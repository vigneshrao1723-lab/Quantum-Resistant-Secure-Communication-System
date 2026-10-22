# Minimal Windows UI Automation agent: reads one JSON command per line on stdin,
# writes one JSON reply per line on stdout. Used by tests/acceptance/desktop_driver.py
# to drive the real Desktop GUI (source or packaged EXE) without extra dependencies.
#
# Commands (all replies: {"ok":true,...} or {"ok":false,"error":"..."}):
#   windows  {pid}                        -> top-level windows of the process
#   tree     {pid, window?}               -> flat list of elements in a window
#   click    {pid, window?, by}           -> invoke / click an element
#   set_text {pid, window?, by, text}     -> set the value of an edit control
#   get_text {pid, window?, by}           -> text / value of an element
#   key      {pid, window?, by?, keys}    -> focus an element and send keys (SendKeys syntax)
#   close    {pid, window?}               -> close a window
# `by` = {id?: substring of AutomationId, name?: exact Name, name_contains?: substring,
#         type?: "Button"|"Edit"|"Text"|..., nth?: zero-based index among matches}

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms, System.Drawing
Add-Type -AssemblyName System.Web.Extensions
Add-Type -ReferencedAssemblies UIAutomationClient, UIAutomationTypes, WindowsBase @"
using System;
using System.Threading;
using System.Windows.Automation;
public static class Legacy {
  // Invoke() also blocks while a modal dialog opened by the click is on screen; same remedy.
  public static void InvokeAsync(AutomationElement element) {
    var pattern = (InvokePattern)element.GetCurrentPattern(InvokePattern.Pattern);
    Exception failure = null;
    var t = new Thread(() => { try { pattern.Invoke(); } catch (Exception e) { failure = e; } });
    t.IsBackground = true;
    t.Start();
    // Still running after a moment = the click opened a modal dialog; that is success. A quick
    // failure is reported rather than swallowed.
    if (t.Join(1500) && failure != null) { throw new InvalidOperationException("Invoke failed: " + failure.Message); }
  }
  // DoDefaultAction() is synchronous; a button whose handler opens a modal dialog would block the
  // caller until the dialog is closed. Run it on its own thread so the agent keeps serving commands.
  public static void DefaultActionAsync(AutomationElement element) {
    var pattern = (LegacyIAccessiblePattern)element.GetCurrentPattern(LegacyIAccessiblePattern.Pattern);
    var t = new Thread(() => { try { pattern.DoDefaultAction(); } catch (Exception) { } });
    t.IsBackground = true;
    t.Start();
  }
}
"@
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Mouse {
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extra);
  public static void ClickAt(int x, int y) {
    SetCursorPos(x, y);
    mouse_event(0x0002, 0, 0, 0, UIntPtr.Zero);
    mouse_event(0x0004, 0, 0, 0, UIntPtr.Zero);
  }
}
"@
[void][Mouse]::SetProcessDPIAware()
$AE = [System.Windows.Automation.AutomationElement]
$TS = [System.Windows.Automation.TreeScope]
$json = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$json.MaxJsonLength = 67108864

function Reply($obj) {
  # ASCII-only output: non-ASCII characters are escaped so the console code page cannot corrupt them.
  $text = $json.Serialize($obj)
  $sb = New-Object System.Text.StringBuilder
  foreach ($ch in $text.ToCharArray()) {
    if ([int]$ch -gt 126) { [void]$sb.Append(('\u{0:x4}' -f [int]$ch)) } else { [void]$sb.Append($ch) }
  }
  [Console]::Out.WriteLine($sb.ToString()); [Console]::Out.Flush()
}

function Get-Windows($procId) {
  $cond = New-Object System.Windows.Automation.PropertyCondition($AE::ProcessIdProperty, [int]$procId)
  $found = $AE::RootElement.FindAll($TS::Children, $cond)
  $list = @(); foreach ($w in $found) { $list += $w }
  return $list
}

function Pick-Window($procId, $title) {
  $wins = Get-Windows $procId
  if (-not $wins -or $wins.Count -eq 0) { throw "no window for pid $procId" }
  if ($title) {
    foreach ($w in $wins) { if ($w.Current.Name -like "*$title*") { return $w } }
    throw "no window titled like '$title'"
  }
  # Prefer the most recently shown modal/dialog: the last top-level window.
  return $wins[$wins.Count - 1]
}

function Type-Name($e) { return $e.Current.ControlType.ProgrammaticName -replace '^ControlType\.', '' }

function Find-All($win, $by) {
  # UI Automation can fail a query for an instant while the application repaints or replaces a
  # control; a short retry is what any client of this API does.
  $all = $null
  for ($attempt = 1; $attempt -le 4; $attempt++) {
    try { $all = $win.FindAll($TS::Descendants, [System.Windows.Automation.Condition]::TrueCondition); break }
    catch { if ($attempt -eq 4) { throw }; Start-Sleep -Milliseconds 250 }
  }
  $out = @()
  foreach ($e in $all) {
    $c = $e.Current
    if ($by.id -and ($c.AutomationId -notlike "*$($by.id)*")) { continue }
    if ($by.name -and ($c.Name -ne $by.name)) { continue }
    if ($by.name_contains -and ($c.Name -notlike "*$($by.name_contains)*")) { continue }
    if ($by.type -and ((Type-Name $e) -ne $by.type)) { continue }
    if ($by.visible_only -and $c.IsOffscreen) { continue }
    $out += $e
  }
  return $out
}

function Resolve-Element($cmd) {
  $win = Pick-Window $cmd.pid $cmd.window
  # Interact with the window the way a person would: bring it to the front first.
  try { $win.SetFocus() } catch {}
  $matches = @(Find-All $win $cmd.by)
  $nth = 0; if ($cmd.by.nth -ne $null) { $nth = [int]$cmd.by.nth }
  if ($matches.Count -le $nth) { throw "element not found (matches=$($matches.Count), nth=$nth)" }
  return $matches[$nth]
}

function Describe($e) {
  $c = $e.Current
  $text = $null
  try { $vp = $e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern); $text = $vp.Current.Value } catch {}
  return @{ type = (Type-Name $e); name = $c.Name; id = $c.AutomationId; enabled = $c.IsEnabled; offscreen = $c.IsOffscreen; value = $text }
}

while (($line = [Console]::In.ReadLine()) -ne $null) {
  if (-not $line.Trim()) { continue }
  try {
    $cmd = $json.DeserializeObject($line)
    switch ($cmd.cmd) {
      'windows' {
        $r = @(); foreach ($w in (Get-Windows $cmd.pid)) { $r += @{ title = $w.Current.Name; id = $w.Current.AutomationId } }
        Reply @{ ok = $true; windows = $r }
      }
      'tree' {
        $win = Pick-Window $cmd.pid $cmd.window
        $r = @(); foreach ($e in (Find-All $win @{})) { $r += (Describe $e) }
        Reply @{ ok = $true; title = $win.Current.Name; elements = $r }
      }
      'click' {
        $e = Resolve-Element $cmd
        $done = $false
        if ($cmd.mouse) {
          # A genuine mouse click (needed for list rows, whose "opened" signal is a click, not a selection).
          $r = $e.Current.BoundingRectangle
          if ($r.IsEmpty -or $e.Current.IsOffscreen) { throw "element is not on screen" }
          [Mouse]::ClickAt([int]($r.X + $r.Width / 2), [int]($r.Y + $r.Height / 2))
          $done = $true
        }
        if (-not $done) { try { [Legacy]::InvokeAsync($e); $done = $true } catch {} }
        if (-not $done) { try { $p = $e.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern); $p.Select(); $done = $true } catch {} }
        if (-not $done) { try { $p = $e.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern); $p.Toggle(); $done = $true } catch {} }
        if (-not $done) { try { $p = $e.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern); $p.Expand(); $done = $true } catch {} }
        if (-not $done) { try { [Legacy]::DefaultActionAsync($e); $done = $true } catch {} }
        if (-not $done) {
          # Last resort: a real mouse click at the control's centre.
          $r = $e.Current.BoundingRectangle
          if ($r.IsEmpty -or $e.Current.IsOffscreen) { throw "element supports no click-like pattern and is not on screen" }
          [Mouse]::ClickAt([int]($r.X + $r.Width / 2), [int]($r.Y + $r.Height / 2))
          $done = $true
        }
        Reply @{ ok = $true }
      }
      'set_text' {
        $e = Resolve-Element $cmd
        $p = $e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
        $p.SetValue([string]$cmd.text)
        Reply @{ ok = $true }
      }
      'get_text' {
        $e = Resolve-Element $cmd
        Reply @{ ok = $true; element = (Describe $e) }
      }
      'key' {
        if ($cmd.by) { $e = Resolve-Element $cmd; $e.SetFocus(); Start-Sleep -Milliseconds 150 }
        [System.Windows.Forms.SendKeys]::SendWait([string]$cmd.keys)
        Reply @{ ok = $true }
      }
      'screenshot' {
        # The window exactly as it is on screen right now (real pixels, not a re-render).
        $win = Pick-Window $cmd.pid $cmd.window
        try { $win.SetFocus() } catch {}
        Start-Sleep -Milliseconds 600
        $r = $win.Current.BoundingRectangle
        $bmp = New-Object System.Drawing.Bitmap([int]$r.Width, [int]$r.Height)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen([int]$r.X, [int]$r.Y, 0, 0, $bmp.Size)
        $g.Dispose()
        $bmp.Save([string]$cmd.path, [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
        Reply @{ ok = $true; width = [int]$r.Width; height = [int]$r.Height }
      }
      'close' {
        $win = Pick-Window $cmd.pid $cmd.window
        $p = $win.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern)
        $p.Close()
        Reply @{ ok = $true }
      }
      default { Reply @{ ok = $false; error = "unknown command $($cmd.cmd)" } }
    }
  } catch {
    Reply @{ ok = $false; error = "$($_.Exception.Message)" }
  }
}
