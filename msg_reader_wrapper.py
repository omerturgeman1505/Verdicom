"""
Msg-Reader Wrapper for Python
Uses the JavaScript Msg-reader library via Node.js to extract attachments from .msg and .eml files.
Based on: https://github.com/Rasalas/msg-reader
"""

import os
import json
import subprocess
import base64
import tempfile
import hashlib
import traceback
from pathlib import Path

# Path to Msg-reader directory
MSG_READER_DIR = Path(__file__).parent / "Msg-reader"
MSG_READER_UTILS = MSG_READER_DIR / "src" / "js" / "utils.js"

def extract_attachments_via_nodejs(file_path, file_type='msg'):
    """
    Extract attachments from MSG or EML files using the Msg-reader JavaScript library.
    
    Args:
        file_path: Path to the .msg or .eml file
        file_type: 'msg' or 'eml'
    
    Returns:
        dict with:
            - attachments: List of attachment dicts with filename, content (bytes), mime_type, etc.
            - headers: Email headers (Subject, From, To, Date, etc.)
            - body: Email body text
            - body_html: Email body HTML
            - success: Boolean indicating if extraction succeeded
            - error: Error message if failed
    """
    result = {
        'attachments': [],
        'headers': {},
        'body': '',
        'body_html': '',
        'success': False,
        'error': None
    }
    
    if not os.path.exists(file_path):
        result['error'] = f"File not found: {file_path}"
        return result
    
    if not MSG_READER_DIR.exists():
        result['error'] = f"Msg-reader directory not found: {MSG_READER_DIR}"
        return result
    
    # Create a Node.js script that will extract the email data
    # Script will be written to Msg-reader directory, so we can use relative paths
    node_script = f"""
const fs = require('fs');
const path = require('path');

// Redirect ALL console methods to stderr so they don't interfere with JSON output
// This is critical - console.log in utils.js prints to stdout and breaks JSON parsing
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;
const originalConsoleLog = console.log;

console.error = function(...args) {{
    // Write to stderr (not stdout)
    process.stderr.write(args.map(a => String(a)).join(' ') + '\\n');
}};
console.warn = function(...args) {{
    // Write to stderr (not stdout)
    process.stderr.write(args.map(a => String(a)).join(' ') + '\\n');
}};
console.log = function(...args) {{
    // CRITICAL: Redirect console.log to stderr to prevent breaking JSON output
    // The utils.js file uses console.log which was breaking JSON parsing
    process.stderr.write(args.map(a => String(a)).join(' ') + '\\n');
}};

// Create a mock window object for browser compatibility (must be before require)
if (typeof window === 'undefined') {{
    global.window = {{}};
}}
// Since script runs from Msg-reader directory, use relative path
const {{ extractMsg, extractEml }} = require('./src/js/utils.js');

const filePath = process.argv[2];
const fileType = process.argv[3] || 'msg';

try {{
    const fileBuffer = fs.readFileSync(filePath);
    let emailData;
    let msgReader = null;
    
    if (fileType === 'msg') {{
        // Extract MSG data - extractMsg returns msgInfo directly
        emailData = extractMsg(fileBuffer);
    }} else if (fileType === 'eml') {{
        emailData = extractEml(fileBuffer);
    }} else {{
        throw new Error(`Unsupported file type: ${{fileType}}`);
    }}
    
    if (!emailData) {{
        throw new Error('Failed to extract email data');
    }}
    
    // Prepare attachments for JSON serialization
    const attachments = [];
    if (emailData.attachments && Array.isArray(emailData.attachments)) {{
        emailData.attachments.forEach((att, index) => {{
            // Extract base64 content from data URI if present
            let contentBase64 = null;
            if (att.contentBase64) {{
                const match = att.contentBase64.match(/^data:[^;]+;base64,(.+)$/);
                if (match) {{
                    contentBase64 = match[1];
                }} else {{
                    // If already base64 without data URI prefix
                    contentBase64 = att.contentBase64;
                }}
            }}
            
            // Get filename from multiple possible fields
            const filename = att.fileName || att.filename || att.fileNameShort || att.name || `attachment_${{index + 1}}`;
            
            attachments.push({{
                filename: filename,
                mime_type: att.attachMimeTag || att.mimeType || 'application/octet-stream',
                content_base64: contentBase64,
                content_id: att.contentId || att.content_id || att.pidContentId || null,
                size: att.contentLength || att.size || att.dataId || 0,
                data_id: att.dataId || null  // Store dataId for potential later retrieval
            }});
        }});
    }}
    
    // Extract headers - handle multiple possible field names
    const headers = {{
        subject: emailData.subject || emailData.subjectPrefix || '',
        from: emailData.senderEmail || emailData.from || emailData.senderName || '',
        from_name: emailData.senderName || emailData.fromName || '',
        to: emailData.recipients ? emailData.recipients
            .filter(r => r.recipType === 'to' || r.recipType === 1)
            .map(r => r.address || r.email || r.displayName || '')
            .filter(e => e)
            .join(', ') : '',
        cc: emailData.recipients ? emailData.recipients
            .filter(r => r.recipType === 'cc' || r.recipType === 2)
            .map(r => r.address || r.email || r.displayName || '')
            .filter(e => e)
            .join(', ') : '',
        date: emailData.messageDeliveryTime || emailData.date || emailData.creationTime || ''
    }};
    
    const output = {{
        success: true,
        headers: headers,
        body: emailData.bodyContent || emailData.body || '',
        body_html: emailData.bodyContentHTML || emailData.bodyHTML || emailData.body || '',
        attachments: attachments
    }};
    
    // Output ONLY JSON to stdout (no extra text, no console.log which may add warnings)
    process.stdout.write(JSON.stringify(output) + '\\n');
    process.exit(0);
}} catch (error) {{
    const errorOutput = {{
        success: false,
        error: error.message || String(error),
        attachments: [],
        headers: {{}},
        body: '',
        body_html: ''
    }};
    // Output ONLY JSON to stdout (no extra text)
    process.stdout.write(JSON.stringify(errorOutput) + '\\n');
    process.exit(1);
}}
"""
    
    try:
        # Write the Node.js script directly to Msg-reader directory so relative imports work
        script_path = MSG_READER_DIR / "temp_extract.js"
        script_path_str = str(script_path)
        
        # Verify paths exist before proceeding
        if not MSG_READER_DIR.exists():
            result['error'] = f"Msg-reader directory not found: {MSG_READER_DIR}"
            return result
        if not MSG_READER_UTILS.exists():
            result['error'] = f"utils.js not found at: {MSG_READER_UTILS}"
            return result
        
        try:
            with open(script_path_str, 'w', encoding='utf-8') as script_file:
                script_file.write(node_script)
        except Exception as write_error:
            result['error'] = f"Failed to write script: {write_error}"
            return result
        
        try:
            # Run the script from Msg-reader directory so it can use relative imports
            # Use absolute path to script to ensure it's found
            process = subprocess.Popen(
                ['node', script_path_str, file_path, file_type],
                cwd=str(MSG_READER_DIR),  # Set working directory for relative imports in script
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'  # Replace encoding errors instead of failing
            )
            
            stdout, stderr = process.communicate(timeout=60)  # 60 second timeout
            
            # Handle None values for stdout/stderr
            if stdout is None:
                stdout = ''
            if stderr is None:
                stderr = ''
            
            # Log stderr for debugging but don't fail on warnings
            if stderr and stderr.strip():
                try:
                    # Safely truncate stderr for logging (handle encoding issues)
                    stderr_preview = stderr[:200] if isinstance(stderr, str) else str(stderr)[:200]
                    print(f"[Msg-Reader] Node.js stderr: {stderr_preview}...")
                except Exception as log_error:
                    print(f"[Msg-Reader] Node.js stderr (error logging): {log_error}")
            
            if process.returncode != 0:
                error_msg = stderr if stderr else (stdout if stdout else "Unknown error")
                result['error'] = f"Node.js process failed: {error_msg}"
                return result
            
            # Parse JSON output - stdout should now be clean JSON only (console.log redirected to stderr)
            stdout_clean = stdout.strip() if stdout else ''
            
            # If stdout is empty or doesn't start with {, check if there's JSON somewhere
            if not stdout_clean or not stdout_clean.startswith('{'):
                # Try to find JSON in the output (fallback in case console.log still leaked)
                json_start = stdout_clean.find('{')
                if json_start < 0:
                    # No JSON found - check stderr for clues
                    print(f"[Msg-Reader] WARNING: No JSON in stdout. Stdout length: {len(stdout)}, Preview: {stdout[:200]}")
                    if stderr:
                        print(f"[Msg-Reader] Stderr preview: {stderr[:200]}")
                    result['error'] = f"No JSON found in output. This may indicate the script failed silently."
                    return result
                stdout_clean = stdout_clean[json_start:]
            
            # Find matching closing brace by counting (handle nested objects)
            brace_count = 0
            json_end = -1
            for i, char in enumerate(stdout_clean):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        json_end = i + 1
                        break
            
            if json_end <= 0:
                # Fallback: try simple approach - find last }
                json_end = stdout_clean.rfind('}') + 1
                if json_end <= 0:
                    print(f"[Msg-Reader] WARNING: Incomplete JSON. Output length: {len(stdout_clean)}, Preview: {stdout_clean[:500]}")
                    result['error'] = f"Incomplete JSON in output. Output may have been truncated."
                    return result
            
            json_str = stdout_clean[:json_end]
            
            try:
                output_data = json.loads(json_str)
                
                if output_data.get('success'):
                    result['success'] = True
                    result['headers'] = output_data.get('headers', {})
                    result['body'] = output_data.get('body', '')
                    result['body_html'] = output_data.get('body_html', '')
                    
                    # Process attachments - decode base64 to bytes
                    attachments_data = output_data.get('attachments', [])
                    for att_data in attachments_data:
                        attachment = {
                            'filename': att_data.get('filename', 'unknown'),
                            'mime_type': att_data.get('mime_type', 'application/octet-stream'),
                            'content_id': att_data.get('content_id'),
                            'size': att_data.get('size', 0)
                        }
                        
                        # Decode base64 content
                        content_base64 = att_data.get('content_base64')
                        if content_base64:
                            try:
                                attachment['content'] = base64.b64decode(content_base64)
                                attachment['size'] = len(attachment['content'])
                                
                                # Calculate hash
                                attachment['hash'] = hashlib.sha256(attachment['content']).hexdigest()
                                
                                result['attachments'].append(attachment)
                            except Exception as decode_error:
                                print(f"[Msg-Reader] Failed to decode attachment {attachment['filename']}: {decode_error}")
                                continue
                        else:
                            # No content available
                            result['attachments'].append(attachment)
                else:
                    result['error'] = output_data.get('error', 'Unknown error')
                    
            except json.JSONDecodeError as json_error:
                # Try harder to extract valid JSON
                print(f"[Msg-Reader] JSON parse error: {json_error}")
                print(f"[Msg-Reader] Output length: {len(stdout)}, First 500 chars: {stdout[:500]}")
                
                # Try multiple strategies to find valid JSON
                try:
                    # Strategy 1: Find complete JSON by matching braces
                    lines = stdout_clean.split('\n')
                    for line in reversed(lines):
                        line = line.strip()
                        if line.startswith('{') and len(line) > 20:
                            # Count braces to ensure it's complete
                            open_count = line.count('{')
                            close_count = line.count('}')
                            if open_count == close_count and open_count > 0:
                                try:
                                    output_data = json.loads(line)
                                    print(f"[Msg-Reader] Successfully parsed JSON from complete line")
                                    # Continue processing with output_data
                                    if output_data.get('success'):
                                        result['success'] = True
                                        result['headers'] = output_data.get('headers', {})
                                        result['body'] = output_data.get('body', '')
                                        result['body_html'] = output_data.get('body_html', '')
                                        # Process attachments if any
                                        attachments_data = output_data.get('attachments', [])
                                        for att_data in attachments_data:
                                            attachment = {
                                                'filename': att_data.get('filename', 'unknown'),
                                                'mime_type': att_data.get('mime_type', 'application/octet-stream'),
                                                'content_id': att_data.get('content_id'),
                                                'size': att_data.get('size', 0)
                                            }
                                            content_base64 = att_data.get('content_base64')
                                            if content_base64:
                                                try:
                                                    attachment['content'] = base64.b64decode(content_base64)
                                                    attachment['size'] = len(attachment['content'])
                                                    attachment['hash'] = hashlib.sha256(attachment['content']).hexdigest()
                                                except:
                                                    pass
                                            result['attachments'].append(attachment)
                                    else:
                                        result['error'] = output_data.get('error', 'Unknown error')
                                    break
                                except:
                                    continue
                    else:
                        raise json_error
                except Exception as e:
                    stdout_preview = stdout[:500] if stdout else "No output"
                    result['error'] = f"Failed to parse JSON output: {json_error}. Attempted recovery also failed: {e}\nOutput preview: {stdout_preview}..."
                    return result
                
        finally:
            # Clean up temporary script file
            try:
                if os.path.exists(script_path):
                    os.unlink(script_path)
            except:
                pass
                
    except subprocess.TimeoutExpired:
        result['error'] = "Node.js process timed out after 60 seconds"
    except UnicodeDecodeError as decode_error:
        result['error'] = f"Encoding error: {str(decode_error)}. The file may contain invalid characters."
        print(f"[Msg-Reader] UnicodeDecodeError: {decode_error}")
        traceback.print_exc()
    except Exception as e:
        error_msg = str(e)
        # Handle NoneType attribute errors
        if "'NoneType' object has no attribute" in error_msg:
            result['error'] = f"Error: Process output was None. This may indicate the Node.js script failed silently. Original error: {error_msg}"
        else:
            result['error'] = f"Error running Node.js extraction: {error_msg}"
        print(f"[Msg-Reader] Exception: {e}")
        traceback.print_exc()
    
    return result


def extract_eml_attachments_python(file_path):
    """
    Extract attachments from EML files using Python's email library.
    This is a fallback if Node.js is not available.
    
    Args:
        file_path: Path to the .eml file
    
    Returns:
        dict with attachments, headers, body, etc.
    """
    import email
    from email import policy
    from email.parser import BytesParser
    
    result = {
        'attachments': [],
        'headers': {},
        'body': '',
        'body_html': '',
        'success': False,
        'error': None
    }
    
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        # Extract headers
        result['headers'] = {
            'subject': msg.get('Subject', ''),
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'cc': msg.get('Cc', ''),
            'date': str(msg.get('Date', ''))
        }
        
        # Extract body
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                
                if 'attachment' in content_disposition or 'inline' in content_disposition:
                    # This is an attachment
                    filename = part.get_filename()
                    if filename:
                        # Decode filename if encoded
                        try:
                            from email.header import decode_header
                            decoded_parts = decode_header(filename)
                            filename = ''.join([
                                part[0].decode(part[1] or 'utf-8') if isinstance(part[0], bytes) else part[0]
                                for part in decoded_parts
                            ])
                        except:
                            pass
                        
                        payload = part.get_payload(decode=True)
                        if payload:
                            attachment = {
                                'filename': filename,
                                'mime_type': content_type,
                                'content': payload,
                                'size': len(payload),
                                'hash': hashlib.sha256(payload).hexdigest()
                            }
                            result['attachments'].append(attachment)
                
                elif content_type == 'text/plain' and not result['body']:
                    payload = part.get_payload(decode=True)
                    if payload:
                        result['body'] = payload.decode('utf-8', errors='ignore')
                
                elif content_type == 'text/html' and not result['body_html']:
                    payload = part.get_payload(decode=True)
                    if payload:
                        result['body_html'] = payload.decode('utf-8', errors='ignore')
        else:
            # Single part message
            payload = msg.get_payload(decode=True)
            if payload:
                content_type = msg.get_content_type()
                if 'html' in content_type:
                    result['body_html'] = payload.decode('utf-8', errors='ignore')
                else:
                    result['body'] = payload.decode('utf-8', errors='ignore')
        
        result['success'] = True
        
    except Exception as e:
        result['error'] = f"Error parsing EML file: {str(e)}"
    
    return result


def extract_email_attachments(file_path):
    """
    Main function to extract attachments from .msg or .eml files.
    Tries Node.js/Msg-reader first, falls back to Python email library for EML.
    
    Args:
        file_path: Path to the email file
    
    Returns:
        dict with attachments, headers, body, etc.
    """
    file_ext = os.path.splitext(file_path)[1].lower()
    
    if file_ext == '.msg':
        # For MSG files, use Node.js/Msg-reader
        return extract_attachments_via_nodejs(file_path, 'msg')
    elif file_ext == '.eml':
        # For EML files, try Node.js first, fallback to Python
        result = extract_attachments_via_nodejs(file_path, 'eml')
        if not result['success']:
            print(f"[Msg-Reader] Node.js extraction failed, trying Python fallback: {result.get('error')}")
            result = extract_eml_attachments_python(file_path)
        return result
    else:
        return {
            'success': False,
            'error': f'Unsupported file type: {file_ext}',
            'attachments': [],
            'headers': {},
            'body': '',
            'body_html': ''
        }

