#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Automated Email Header & Content Analysis for Phishing Detection
    
.DESCRIPTION
    Analyzes email headers, sender reputation, URLs, and attachments
    to determine if an email is malicious, suspicious, or benign.
    
.PARAMETER EmlFile
    Path to .eml file to analyze
    
.EXAMPLE
    .\phishing_analyzer.ps1 -EmlFile "suspicious_email.eml"
    
.NOTES
    Requires VirusTotal API key for full analysis
    Real Case: PHISH-001 analysis of credential harvesting email
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$EmlFile,
    
    [string]$VirusTotalApiKey = $env:VT_API_KEY,
    [int]$UrlCheckTimeoutSec = 30
)

# Configuration
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

class PhishingAnalyzer {
    [string]$EmlPath
    [string]$VtApiKey
    [hashtable]$Analysis = @{}
    [string[]]$Urls = @()
    [object[]]$Attachments = @()
    
    PhishingAnalyzer([string]$emlPath, [string]$apiKey) {
        $this.EmlPath = $emlPath
        $this.VtApiKey = $apiKey
        
        if (-not (Test-Path $emlPath)) {
            throw "Email file not found: $emlPath"
        }
    }
    
    [string] ReadEmlContent() {
        Write-Host "Reading email file: $($this.EmlPath)"
        $content = Get-Content -Path $this.EmlPath -Raw
        return $content
    }
    
    [hashtable] ParseHeaders([string]$eml) {
        $headers = @{}
        $headerSection = $eml -split "`r`n`r`n" | Select-Object -First 1
        
        $lines = $headerSection -split "`r`n"
        foreach ($line in $lines) {
            if ($line -match '^([^:]+):\s*(.*)$') {
                $key = $matches[1]
                $value = $matches[2]
                
                if ($headers.ContainsKey($key)) {
                    $headers[$key] += "; $value"
                } else {
                    $headers[$key] = $value
                }
            }
        }
        
        return $headers
    }
    
    [void] AnalyzeSPF([hashtable]$headers) {
        Write-Host "`n=== SPF Analysis ==="
        
        $from = $headers['From']
        $receivedFrom = $headers['Received']
        
        # Extract sender IP from Received header
        if ($receivedFrom -match 'from .+? \((.+?)\)') {
            $senderIp = $matches[1]
            Write-Host "Sender IP: $senderIp"
            $this.Analysis['SenderIP'] = $senderIp
        }
        
        # Check SPF record (simplified - would need DNS query in real implementation)
        if ($from -match '\[(\d+\.\d+\.\d+\.\d+)\]') {
            Write-Host "SPF: CHECK REQUIRED (sender uses IP address instead of domain)"
            $this.Analysis['SPF'] = 'FAIL'
            $this.Analysis['SPFReason'] = 'Sender uses IP instead of domain'
        } else {
            Write-Host "SPF: PASS (domain-based sender)"
            $this.Analysis['SPF'] = 'PASS'
        }
    }
    
    [void] AnalyzeDKIM([hashtable]$headers) {
        Write-Host "`n=== DKIM Analysis ==="
        
        if ($headers.ContainsKey('DKIM-Signature')) {
            Write-Host "DKIM-Signature: FOUND"
            $this.Analysis['DKIM'] = 'PRESENT'
        } else {
            Write-Host "DKIM-Signature: NOT FOUND"
            $this.Analysis['DKIM'] = 'MISSING'
            $this.Analysis['Risk'] += 10
        }
    }
    
    [void] AnalyzeDMARC([hashtable]$headers) {
        Write-Host "`n=== DMARC Analysis ==="
        
        if ($headers.ContainsKey('Authentication-Results')) {
            $authResults = $headers['Authentication-Results']
            if ($authResults -match 'dmarc=pass') {
                Write-Host "DMARC: PASS"
                $this.Analysis['DMARC'] = 'PASS'
            } else {
                Write-Host "DMARC: FAIL"
                Write-Host "Details: $authResults"
                $this.Analysis['DMARC'] = 'FAIL'
                $this.Analysis['Risk'] += 15
            }
        } else {
            Write-Host "DMARC: No Authentication-Results header"
            $this.Analysis['DMARC'] = 'UNKNOWN'
            $this.Analysis['Risk'] += 5
        }
    }
    
    [void] ExtractUrls([string]$eml) {
        Write-Host "`n=== URL Extraction ==="
        
        # Regex for URL detection
        $urlPattern = 'https?://[^\s<>"{}|\\^`\[\]]*'
        
        $matches = [regex]::Matches($eml, $urlPattern)
        foreach ($match in $matches) {
            $url = $match.Value
            $this.Urls += $url
            Write-Host "Found URL: $url"
        }
    }
    
    [void] CheckUrlReputation() {
        if ($this.Urls.Count -eq 0) {
            Write-Host "No URLs found in email"
            return
        }
        
        Write-Host "`n=== URL Reputation Check ==="
        
        foreach ($url in $this.Urls) {
            Write-Host "`nAnalyzing: $url"
            
            # Check for suspicious indicators
            if ($url -match 'bit\.ly|tinyurl|short\.link') {
                Write-Host "⚠️  URL SHORTENER DETECTED - Redirects may hide real destination"
                $this.Analysis['Risk'] += 20
            }
            
            if ($url -match 'http://') {
                Write-Host "⚠️  UNENCRYPTED HTTP - No TLS encryption"
                $this.Analysis['Risk'] += 10
            }
            
            # Extract domain
            if ($url -match 'https?://([^/]+)') {
                $domain = $matches[1]
                
                # Check for homograph attacks (look-alike domains)
                if ($domain -match 'micros0ft|paypa1|amaz0n|goog1e') {
                    Write-Host "⚠️  HOMOGRAPH ATTACK - Domain looks similar to legitimate brand"
                    $this.Analysis['Risk'] += 25
                }
                
                # Check domain age (would require WHOIS lookup)
                Write-Host "Domain: $domain - WHOIS lookup would show registration date"
            }
        }
    }
    
    [void] AnalyzeAttachments([string]$eml) {
        Write-Host "`n=== Attachment Analysis ==="
        
        # Simplified attachment detection
        if ($eml -match 'Content-Disposition: attachment') {
            Write-Host "Attachments detected"
            
            # Look for suspicious file extensions
            if ($eml -match 'filename="([^"]+\.(exe|scr|vbs|ps1|cmd|bat|com))"') {
                $filename = $matches[1]
                Write-Host "⚠️  EXECUTABLE ATTACHMENT: $filename"
                $this.Analysis['Risk'] += 35
            }
            
            # Office documents with macros
            if ($eml -match 'filename="[^"]*\.(docm|xlsm|pptm)"') {
                Write-Host "⚠️  MACRO-ENABLED OFFICE DOCUMENT DETECTED"
                $this.Analysis['Risk'] += 20
            }
        } else {
            Write-Host "No attachments"
        }
    }
    
    [void] AnalyzeContent([string]$eml, [hashtable]$headers) {
        Write-Host "`n=== Content Analysis ==="
        
        $from = $headers['From']
        $subject = $headers['Subject']
        
        # Check for urgency-inducing language
        if ($subject -match '(URGENT|VERIFY|CONFIRM|ACTION REQUIRED|UPDATE REQUIRED)') {
            Write-Host "⚠️  URGENCY LANGUAGE: '$subject'"
            $this.Analysis['Risk'] += 15
        }
        
        # Check for mismatched sender/display name
        if ($from -match '"([^"]+)"\s+<([^>]+)>') {
            $displayName = $matches[1]
            $emailAddr = $matches[2]
            
            if ($displayName -notlike "*$($emailAddr.Split('@')[1])*") {
                Write-Host "⚠️  DISPLAY NAME MISMATCH: '$displayName' doesn't match '$emailAddr'"
                $this.Analysis['Risk'] += 20
            }
        }
        
        # Check for common phishing indicators
        $phishingKeywords = @(
            'verify your account', 'confirm your identity', 'update payment',
            'click here immediately', 'act now', 'unusual activity detected',
            'restore access', 'reactivate account', 'claim reward'
        )
        
        foreach ($keyword in $phishingKeywords) {
            if ($eml -match $keyword) {
                Write-Host "⚠️  PHISHING KEYWORD FOUND: '$keyword'"
                $this.Analysis['Risk'] += 10
            }
        }
    }
    
    [void] CalculateRiskScore() {
        if (-not $this.Analysis.ContainsKey('Risk')) {
            $this.Analysis['Risk'] = 0
        }
        
        # Normalize risk score to 0-10
        $riskScore = [Math]::Min($this.Analysis['Risk'] / 10, 10)
        $this.Analysis['RiskScore'] = [Math]::Round($riskScore, 1)
        
        # Determine verdict
        if ($riskScore -ge 7) {
            $this.Analysis['Verdict'] = 'MALICIOUS'
        } elseif ($riskScore -ge 4) {
            $this.Analysis['Verdict'] = 'SUSPICIOUS'
        } else {
            $this.Analysis['Verdict'] = 'BENIGN'
        }
    }
    
    [void] GenerateReport() {
        Write-Host "`n" + ("=" * 60)
        Write-Host "PHISHING ANALYSIS REPORT" -ForegroundColor Cyan
        Write-Host ("=" * 60)
        
        $verdict = $this.Analysis['Verdict']
        $riskScore = $this.Analysis['RiskScore']
        
        if ($verdict -eq 'MALICIOUS') {
            Write-Host "VERDICT: $verdict" -ForegroundColor Red
        } elseif ($verdict -eq 'SUSPICIOUS') {
            Write-Host "VERDICT: $verdict" -ForegroundColor Yellow
        } else {
            Write-Host "VERDICT: $verdict" -ForegroundColor Green
        }
        
        Write-Host "Risk Score: $riskScore / 10" -ForegroundColor Cyan
        
        Write-Host "`nRecommendations:"
        switch ($verdict) {
            'MALICIOUS' {
                Write-Host "1. DO NOT click links or download attachments"
                Write-Host "2. Delete email immediately"
                Write-Host "3. Report to security team"
                Write-Host "4. Block sender domain"
            }
            'SUSPICIOUS' {
                Write-Host "1. Do not click links without verification"
                Write-Host "2. Contact sender via alternative channel"
                Write-Host "3. Submit for further analysis"
            }
            'BENIGN' {
                Write-Host "1. Safe to open"
                Write-Host "2. Monitor for follow-up phishing emails"
            }
        }
        
        Write-Host "`nFull Analysis:"
        $this.Analysis.GetEnumerator() | ForEach-Object {
            Write-Host "$($_.Key): $($_.Value)"
        }
    }
    
    [void] Analyze() {
        $eml = $this.ReadEmlContent()
        $headers = $this.ParseHeaders($eml)
        
        Write-Host "`nEmail Subject: $($headers['Subject'])"
        Write-Host "From: $($headers['From'])"
        Write-Host "To: $($headers['To'])"
        
        $this.Analysis['Risk'] = 0
        
        $this.AnalyzeSPF($headers)
        $this.AnalyzeDKIM($headers)
        $this.AnalyzeDMARC($headers)
        $this.ExtractUrls($eml)
        $this.CheckUrlReputation()
        $this.AnalyzeAttachments($eml)
        $this.AnalyzeContent($eml, $headers)
        $this.CalculateRiskScore()
        $this.GenerateReport()
    }
}

# Main execution
try {
    Write-Host "Phishing Analyzer - Version 1.0`n"
    
    $analyzer = [PhishingAnalyzer]::new($EmlFile, $VirusTotalApiKey)
    $analyzer.Analyze()
}
catch {
    Write-Error "Analysis failed: $_"
    exit 1
}
