{
    "C:\\Users\\tanma\\OneDrive\\Desktop\\PBL\\scodescanner\\scodescanner\\rules\\php/rule_dangerous_func.yaml": [
        {
            "id": "rules",
            "line": [
                {
                    "null": [
                        [
                            {
                                "id": "Rule_dangerous_funct = $replace",
                                "languages": [
                                    "php"
                                ],
                                "message": "Variable $replace - Found inside dangerous function.`",
                                "mode": "taint",
                                "pattern-sanitizers": [
                                    {
                                        "patterns": [
                                            {
                                                "pattern": "$X"
                                            },
                                            {
                                                "pattern-inside": "...\n$SANITIZER_FUNCS($X);\n"
                                            },
                                            {
                                                "pattern-inside": "$SANITIZER_FUNCS($X);\n...\n"
                                            },
                                            {
                                                "metavariable-regex": {
                                                    "metavariable": "$SANITIZER_FUNCS",
                                                    "regex": "esc_html|esc_attr|htmlspecialchars"
                                                }
                                            }
                                        ]
                                    }
                                ],
                                "pattern-sinks": [
                                    {
                                        "patterns": [
                                            {
                                                "pattern-inside": "$DANGEROUS_FUNCS(...)"
                                            },
                                            {
                                                "metavariable-regex": {
                                                    "metavariable": "$DANGEROUS_FUNCS",
                                                    "regex": "system|eval|passthru|exec|shell_exec|loadXML|curl_exe|include|file_put_contents|file_get_contents|fopen|fsockopen|curl_exec|curl_setopt|unserialize"
                                                }
                                            }
                                        ]
                                    }
                                ],
                                "pattern-sources": [
                                    {
                                        "patterns": [
                                            {
                                                "pattern-either": [
                                                    {
                                                        "pattern": "$replace"
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "severity": "WARNING"
                            }
                        ]
                    ]
                }
            ],
            "lineno": null,
            "message": "No vulnerable RBAC permisions found",
            "severity": null
        }
    ]
}{
    "C:\\Users\\tanma\\OneDrive\\Desktop\\PBL\\scodescanner\\scodescanner\\rules\\php/rule_open_redir.yaml": [
        {
            "id": "rules",
            "line": [
                {
                    "null": [
                        [
                            {
                                "id": "Rule-OpenRedirect = $replace",
                                "languages": [
                                    "php"
                                ],
                                "message": "Possible OpenRedirect/CRLF Injection for variable -  $replace",
                                "patterns": [
                                    {
                                        "pattern-either": [
                                            {
                                                "pattern": "header($X.$replace)"
                                            }
                                        ]
                                    }
                                ],
                                "severity": "WARNING"
                            }
                        ]
                    ]
                }
            ],
            "lineno": null,
            "message": "No vulnerable RBAC permisions found",
            "severity": null
        }
    ]
}{
    "C:\\Users\\tanma\\OneDrive\\Desktop\\PBL\\scodescanner\\scodescanner\\rules\\php/rule_sqli.yaml": [
        {
            "id": "rules",
            "line": [
                {
                    "null": [
                        [
                            {
                                "id": "Rule_SQLi = $replace",
                                "languages": [
                                    "php"
                                ],
                                "message": "Possible SQL Injection for variable -  $replace",
                                "mode": "taint",
                                "pattern-sanitizers": [
                                    {
                                        "patterns": [
                                            {
                                                "pattern": "$replace"
                                            },
                                            {
                                                "pattern-inside": "is_numeric($replace);\n...\n"
                                            }
                                        ]
                                    }
                                ],
                                "pattern-sinks": [
                                    {
                                        "patterns": [
                                            {
                                                "pattern": "$replace"
                                            },
                                            {
                                                "pattern-inside": "$FUNC"
                                            },
                                            {
                                                "metavariable-regex": {
                                                    "metavariable": "$FUNC",
                                                    "regex": "\\\"SELECT.[\\*\\w+,].*FROM.[\\w+,].*WHERE.[\\w+,].*|[\\'\\\"]DELETE.FROM.[\\w+].*[\\'\\\"]|[\\'\\\"]SELECT.*[\\'\\\"]"
                                                }
                                            }
                                        ]
                                    }
                                ],
                                "pattern-sources": [
                                    {
                                        "patterns": [
                                            {
                                                "pattern-either": [
                                                    {
                                                        "pattern": "$replace"
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "severity": "WARNING"
                            }
                        ]
                    ]
                }
            ],
            "lineno": null,
            "message": "No vulnerable RBAC permisions found",
            "severity": null
        }
    ]
}{
    "C:\\Users\\tanma\\OneDrive\\Desktop\\PBL\\scodescanner\\scodescanner\\rules\\php/rule_xss.yaml": [
        {
            "id": "rules",
            "line": [
                {
                    "null": [
                        [
                            {
                                "id": "Rule_XSS = $replace",
                                "languages": [
                                    "php"
                                ],
                                "message": "Variable $replace - Vulnerable to Cross-Site Scripting `",
                                "mode": "taint",
                                "pattern-sanitizers": [
                                    {
                                        "patterns": [
                                            {
                                                "pattern": "$X"
                                            },
                                            {
                                                "pattern-inside": "...\n$SANITIZER_FUNCS($X);\n"
                                            },
                                            {
                                                "pattern-inside": "$SANITIZER_FUNCS($X);\n...\n"
                                            },
                                            {
                                                "metavariable-regex": {
                                                    "metavariable": "$SANITIZER_FUNCS",
                                                    "regex": "esc_html|esc_attr|htmlspecialchars"
                                                }
                                            }
                                        ]
                                    }
                                ],
                                "pattern-sinks": [
                                    {
                                        "pattern-regex": "echo.*"
                                    }
                                ],
                                "pattern-sources": [
                                    {
                                        "patterns": [
                                            {
                                                "pattern-either": [
                                                    {
                                                        "pattern": "$replace"
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "severity": "WARNING"
                            }
                        ]
                    ]
                }
            ],
            "lineno": null,
            "message": "No vulnerable RBAC permisions found",
            "severity": null
        }
    ]
}{
    "C:\\Users\\tanma\\OneDrive\\Desktop\\PBL\\scodescanner\\scodescanner\\rules\\yaml/rules.yaml": [
        {
            "id": "rules",
            "line": [
                {
                    "null": [
                        [
                            {
                                "id": "image",
                                "message": "Alert - Image version used instead of latest - Please Check if version is latest",
                                "regex": "image\\s*\\:\\s+\\w+\\:\\d+.+",
                                "severity": "Low"
                            },
                            {
                                "id": "automountServiceAccountToken",
                                "message": "Alert - SA Token is mounted inside POD - Please change it to false if it is not required.",
                                "regex": "automountServiceAccountToken\\s*\\:\\s+(:?true|True)",
                                "severity": "Low"
                            },
                            {
                                "id": "env",
                                "message": "Alert - ENV Variable used - Please use vault instead.",
                                "regex": "env\\s*\\:\\s+.+",
                                "severity": "Medium"
                            },
                            {
                                "id": "nodePort",
                                "message": "Alert - nodePort will allow the application to accessible pubclily.",
                                "regex": "nodePort\\s*\\:+\\s+\\d+",
                                "severity": "Low"
                            },
                            {
                                "id": "rules",
                                "message": "None",
                                "regex": "rules\\s*\\:\\s+",
                                "scan": true,
                                "severity": "None"
                            },
                            {
                                "id": "volumes",
                                "message": "None",
                                "regex": "volumes\\s*\\:\\s+",
                                "scan": true,
                                "severity": "None"
                            },
                            {
                                "id": "privileged",
                                "message": "Alert - Privileged flag found to set True.",
                                "regex": "privileged\\s*\\:\\s+(:?true|True)",
                                "severity": "High"
                            },
                            {
                                "id": "allowPrivilegeEscalation",
                                "message": "Alert - Privilege Escalation found to set True.",
                                "regex": "allowPrivilegeEscalation\\s*\\:\\s+(:?true|True)",
                                "severity": "Medium"
                            },
                            {
                                "id": "allowedCapabilities",
                                "message": "None",
                                "regex": "allowedCapabilities\\s*\\:\\s*",
                                "scan": true,
                                "severity": "None"
                            },
                            {
                                "id": "pod-security.kubernetes.io/enforce",
                                "message": "Alert - Found Enforced High Privileged POD Security Policy",
                                "regex": "pod-security.kubernetes.io/enforce\\s*\\:\\s+privileged",
                                "severity": "High"
                            },
                            {
                                "id": "pod-security.kubernetes.io/audit",
                                "message": "Alert - Found Privileged POD Security Policy with Audit log enabled",
                                "regex": "pod-security.kubernetes.io/audit\\s*\\:\\s+privileged",
                                "severity": "High"
                            },
                            {
                                "id": "pod-security.kubernetes.io/warn",
                                "message": "Alert - Found Privileged POD Security Policy with Warning enabled",
                                "regex": "pod-security.kubernetes.io/warn\\s*\\:\\s+privileged",
                                "severity": "High"
                            }
                        ]
                    ]
                }
            ],
            "lineno": null,
            "message": "No vulnerable RBAC permisions found",
            "severity": null
        }
    ]
}