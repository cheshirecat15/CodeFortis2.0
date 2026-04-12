import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Check, ChevronDown, Loader2, Play, RotateCcw } from "lucide-react";
import { useState } from "react";
import type { OWASPCategory, SupportedLanguage } from "../types/rules";

const LANGUAGES: { value: SupportedLanguage; label: string }[] = [
  { value: "javascript", label: "JavaScript" },
  { value: "typescript", label: "TypeScript" },
  { value: "python", label: "Python" },
  { value: "java", label: "Java" },
  { value: "php", label: "PHP" },
  { value: "go", label: "Go" },
  { value: "csharp", label: "C#" },
];

const OWASP_CATEGORIES: OWASPCategory[] = [
  "A01:2021 – Broken Access Control",
  "A02:2021 – Cryptographic Failures",
  "A03:2021 – Injection",
  "A04:2021 – Insecure Design",
  "A05:2021 – Security Misconfiguration",
  "A06:2021 – Vulnerable and Outdated Components",
  "A07:2021 – Identification and Authentication Failures",
  "A08:2021 – Software and Data Integrity Failures",
  "A09:2021 – Security Logging and Monitoring Failures",
  "A10:2021 – Server-Side Request Forgery (SSRF)",
];

const EXAMPLE_SNIPPETS: Record<SupportedLanguage, string> = {
  javascript: `// Example: Vulnerable Node.js/Express code
const express = require('express');
const app = express();
const db = require('./db');

// SQL Injection vulnerability
app.get('/user', async (req, res) => {
  const userId = req.query.id;
  const result = await db.query("SELECT * FROM users WHERE id = " + userId);
  res.json(result);
});

// XSS vulnerability
app.get('/search', (req, res) => {
  const query = req.query.q;
  document.getElementById('results').innerHTML = query;
});

// Hardcoded secret
const API_KEY = "sk-prod-abc123xyz789secretkey";

// Command injection
const { exec } = require('child_process');
app.post('/convert', (req, res) => {
  exec("convert " + req.body.filename, (err, stdout) => {
    res.send(stdout);
  });
});

// Insecure random for token
const token = Math.random().toString(36).substring(2);`,
  typescript: `// Example: Vulnerable TypeScript code
import express from 'express';
import jwt from 'jsonwebtoken';

const app = express();

// JWT without proper verification
app.get('/profile', (req, res) => {
  const token = req.headers.authorization;
  const decoded = jwt.verify(token, secret, { algorithms: ["none"] });
  res.json(decoded);
});

// Prototype pollution
app.post('/config', (req, res) => {
  const config = Object.assign({}, req.body);
  res.json(config);
});

// Open redirect
app.get('/login', (req, res) => {
  res.redirect(req.query.next);
});`,
  python: `# Example: Vulnerable Python code
import os
import pickle
import hashlib
from flask import Flask, request

app = Flask(__name__)

# Command injection
@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = os.system("ping -c 1 " + host)
    return str(result)

# Insecure deserialization
@app.route('/load', methods=['POST'])
def load_data():
    data = pickle.loads(request.data)
    return str(data)

# Weak hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Path traversal
@app.route('/file')
def get_file():
    filename = request.args.get('name')
    with open('/var/www/files/' + filename) as f:
        return f.read()`,
  java: `// Example: Vulnerable Java code
import java.sql.*;
import javax.xml.parsers.*;

public class VulnerableApp {
    // SQL Injection
    public User getUser(String userId) throws Exception {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM users WHERE id = " + userId
        );
        return mapUser(rs);
    }
    
    // XXE vulnerability
    public void parseXML(InputStream input) throws Exception {
        DocumentBuilder builder = DocumentBuilderFactory
            .newInstance().newDocumentBuilder();
        Document doc = builder.parse(input);
    }
    
    // Weak crypto
    public String hashData(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(data.getBytes()));
    }
}`,
  php: `<?php
// Example: Vulnerable PHP code

// SQL Injection
$userId = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id = " . $userId);

// Command injection
$filename = $_POST['file'];
$output = shell_exec("cat " . $filename);
echo $output;

// Hardcoded credentials
$db_password = "super_secret_db_pass_123";

// Path traversal
$file = $_GET['page'];
include('/var/www/pages/' . $file);

// Insecure deserialization
$data = unserialize($_COOKIE['user_data']);
?>`,
  go: `// Example: Vulnerable Go code
package main

import (
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
)

// Path traversal
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    data, err := ioutil.ReadFile("/var/www/" + filename)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    fmt.Fprint(w, string(data))
}

// SSRF
func fetchURL(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    resp, _ := http.Get(url)
    defer resp.Body.Close()
}`,
  csharp: `// Example: Vulnerable C# code
using System;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Xml;

public class VulnerableController {
    // SQL Injection
    public User GetUser(string userId) {
        var conn = new SqlConnection(connectionString);
        var cmd = new SqlCommand(
            "SELECT * FROM Users WHERE Id = " + userId, conn
        );
        return ReadUser(cmd.ExecuteReader());
    }
    
    // Weak crypto
    public string HashPassword(string password) {
        using var md5 = MD5.Create();
        var hash = md5.ComputeHash(
            System.Text.Encoding.UTF8.GetBytes(password)
        );
        return Convert.ToBase64String(hash);
    }
    
    // XXE
    public void ParseXml(string xmlContent) {
        var doc = new XmlDocument();
        doc.LoadXml(xmlContent);
    }
}`,
};

interface CodeInputPanelProps {
  code: string;
  language: SupportedLanguage;
  selectedCategories: OWASPCategory[];
  isAnalyzing: boolean;
  onCodeChange: (code: string) => void;
  onLanguageChange: (lang: SupportedLanguage) => void;
  onCategoriesChange: (cats: OWASPCategory[]) => void;
  onAnalyze: () => void;
  onReset: () => void;
}

export function CodeInputPanel({
  code,
  language,
  selectedCategories,
  isAnalyzing,
  onCodeChange,
  onLanguageChange,
  onCategoriesChange,
  onAnalyze,
  onReset,
}: CodeInputPanelProps) {
  const toggleCategory = (cat: OWASPCategory) => {
    if (selectedCategories.includes(cat)) {
      onCategoriesChange(selectedCategories.filter((c) => c !== cat));
    } else {
      onCategoriesChange([...selectedCategories, cat]);
    }
  };

  const selectAllCategories = () => {
    onCategoriesChange([...OWASP_CATEGORIES]);
  };

  const clearCategories = () => {
    onCategoriesChange([]);
  };

  const loadExample = () => {
    onCodeChange(EXAMPLE_SNIPPETS[language]);
  };

  const categoryLabel =
    selectedCategories.length === 0
      ? "None selected"
      : selectedCategories.length === OWASP_CATEGORIES.length
        ? "All categories"
        : `${selectedCategories.length} selected`;

  return (
    <div className="space-y-4">
      {/* Controls row */}
      <div className="flex flex-wrap gap-3 items-end">
        <div className="flex flex-col gap-1.5 min-w-[160px]">
          <Label
            className="text-xs font-mono uppercase tracking-widest"
            style={{ color: "oklch(0.50 0.04 200)", letterSpacing: "0.12em" }}
          >
            Language
          </Label>
          <Select
            value={language}
            onValueChange={(v) => onLanguageChange(v as SupportedLanguage)}
          >
            <SelectTrigger
              className="h-9 text-sm font-mono"
              style={{
                background: "oklch(0.10 0.018 260)",
                border: "1px solid oklch(0.22 0.04 200 / 0.6)",
                color: "oklch(0.88 0.04 160)",
              }}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent
              style={{
                background: "oklch(0.12 0.02 260)",
                border: "1px solid oklch(0.22 0.04 200 / 0.6)",
              }}
            >
              {LANGUAGES.map((lang) => (
                <SelectItem
                  key={lang.value}
                  value={lang.value}
                  className="font-mono text-sm"
                >
                  {lang.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="flex flex-col gap-1.5 min-w-[200px]">
          <Label
            className="text-xs font-mono uppercase tracking-widest"
            style={{ color: "oklch(0.50 0.04 200)", letterSpacing: "0.12em" }}
          >
            OWASP Categories
          </Label>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                className="h-9 text-sm justify-between font-mono min-w-[200px]"
                style={{
                  background: "oklch(0.10 0.018 260)",
                  border: "1px solid oklch(0.22 0.04 200 / 0.6)",
                  color: "oklch(0.88 0.04 160)",
                }}
              >
                <span className="truncate">{categoryLabel}</span>
                <ChevronDown className="w-4 h-4 ml-2 shrink-0 opacity-50" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              className="w-80"
              style={{
                background: "oklch(0.12 0.02 260)",
                border: "1px solid oklch(0.22 0.04 200 / 0.6)",
              }}
              align="start"
            >
              <DropdownMenuLabel
                className="text-xs font-mono"
                style={{ color: "oklch(0.50 0.04 200)" }}
              >
                Filter by OWASP Top 10
              </DropdownMenuLabel>
              <DropdownMenuSeparator
                style={{ background: "oklch(0.22 0.04 200 / 0.4)" }}
              />
              <div className="flex gap-2 px-2 py-1">
                <button
                  type="button"
                  onClick={selectAllCategories}
                  className="text-xs font-mono px-2 py-0.5 rounded-sm transition-colors"
                  style={{ color: "oklch(0.85 0.26 145)" }}
                >
                  All
                </button>
                <button
                  type="button"
                  onClick={clearCategories}
                  className="text-xs font-mono px-2 py-0.5 rounded-sm transition-colors"
                  style={{ color: "oklch(0.50 0.04 200)" }}
                >
                  None
                </button>
              </div>
              <DropdownMenuSeparator
                style={{ background: "oklch(0.22 0.04 200 / 0.4)" }}
              />
              {OWASP_CATEGORIES.map((cat) => (
                <DropdownMenuCheckboxItem
                  key={cat}
                  checked={selectedCategories.includes(cat)}
                  onCheckedChange={() => toggleCategory(cat)}
                  className="text-xs font-mono"
                >
                  {cat}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        <div className="flex gap-2 ml-auto items-end">
          <Button
            variant="ghost"
            size="sm"
            onClick={loadExample}
            className="h-9 text-xs font-mono"
            style={{ color: "oklch(0.50 0.04 200)" }}
          >
            Load Example
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={onReset}
            disabled={isAnalyzing}
            className="h-9 text-xs font-mono gap-1.5"
            style={{ color: "oklch(0.50 0.04 200)" }}
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset
          </Button>
          <Button
            size="sm"
            onClick={onAnalyze}
            disabled={isAnalyzing || !code.trim()}
            className="h-9 text-xs font-mono gap-1.5 font-bold tracking-widest transition-all duration-200"
            style={{
              background: isAnalyzing
                ? "oklch(0.14 0.02 260)"
                : "oklch(0.82 0.22 155)",
              color: isAnalyzing
                ? "oklch(0.50 0.04 200)"
                : "oklch(0.06 0.01 260)",
              border: "1px solid oklch(0.85 0.26 145 / 0.6)",
              boxShadow: isAnalyzing
                ? "none"
                : "0 0 16px oklch(0.85 0.26 145 / 0.4)",
              letterSpacing: "0.1em",
            }}
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                SCANNING...
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                RUN ANALYSIS
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Textarea */}
      <div className="relative">
        <textarea
          value={code}
          onChange={(e) => onCodeChange(e.target.value)}
          placeholder={`// Paste ${LANGUAGES.find((l) => l.value === language)?.label ?? "code"} here...\n// The scanner will detect OWASP Top 10 vulnerabilities client-side.`}
          disabled={isAnalyzing}
          rows={18}
          className="w-full resize-y text-sm font-mono rounded-sm p-4 outline-none transition-all duration-200 placeholder:opacity-40"
          style={{
            background: "oklch(0.07 0.015 260)",
            border: "1px solid oklch(0.22 0.04 200 / 0.5)",
            color: "oklch(0.85 0.26 145)",
            caretColor: "oklch(0.85 0.26 145)",
            boxShadow: "inset 0 0 20px oklch(0.07 0.015 260 / 0.5)",
          }}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
        />
        {/* Scan line overlay when analyzing */}
        {isAnalyzing && (
          <div
            className="absolute inset-0 pointer-events-none overflow-hidden rounded-sm"
            aria-hidden="true"
          >
            <div
              style={{
                position: "absolute",
                left: 0,
                right: 0,
                height: 2,
                background:
                  "linear-gradient(90deg, transparent, oklch(0.85 0.26 145 / 0.8), transparent)",
                boxShadow: "0 0 12px oklch(0.85 0.26 145 / 0.6)",
                animation: "scan-line 1.8s ease-in-out infinite",
              }}
            />
          </div>
        )}
      </div>

      {/* Character count */}
      <div className="flex justify-between items-center">
        <span
          className="text-xs font-mono"
          style={{ color: "oklch(0.35 0.03 200)" }}
        >
          {code.length > 0
            ? `${code.split("\n").length} lines · ${code.length} chars`
            : "No input"}
        </span>
        {selectedCategories.length < OWASP_CATEGORIES.length && (
          <span
            className="text-xs font-mono"
            style={{ color: "oklch(0.50 0.04 200)" }}
          >
            Scanning {selectedCategories.length}/{OWASP_CATEGORIES.length}{" "}
            categories
          </span>
        )}
      </div>
    </div>
  );
}
