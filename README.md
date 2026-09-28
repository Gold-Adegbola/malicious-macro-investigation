# Macro-ni Malicious Macro Investigation

A hands-on investigation of a malicious Word macro document (`Macroni.docm`) from the Blue Team Labs Online Macro-ni challenge. I extracted the VBA, followed the layers of obfuscation, and recovered the command and control (C2) IP address.

**[Read the full investigation report (PDF)](Macro-ni_Malware_Investigation_Documentation_.pdf)**

## Objective

Work out what a suspicious Word document does when it is opened, and follow the payload until I understand what it eventually executes or contacts.

## Questions I Started With

- Why did the email bypass the filter?
- What is inside the Word document?
- Does it contain macros?
- What does the PowerShell contain?
- Is something encoded or encrypted?
- What does it eventually execute or contact?

## Tools Used

- `olevba` (oletools) to extract and analyse the VBA
- `grep`, `cut` and `tr` to rebuild the PowerShell payload from the macro output
- CyberChef to decode Base64, decompress GZIP and apply XOR

## Investigation Flow

1. Identified the file as `Macroni.docm`, a macro-enabled Word document that can contain VBA.
2. Ran `olevba` and found auto-execute procedures (`Document_Open()` and `Workbook_Open()`), which run code as soon as the document is opened.
3. Found a hidden PowerShell command using `-nop -w hidden -encodedcommand`, built piece by piece with repeated `pl = pl & "..."` lines.
4. Rebuilt the full command with `grep`, `cut` and `tr`, then decoded the Base64 (UTF-16LE) in CyberChef.
5. Spotted `H4sIA` at the start of the next blob, a common sign of GZIP-compressed Base64.
6. Decoded that layer with From Base64 and Gunzip to reveal a script containing the byte array `$var_code`.
7. Found the line `$var_code[$x] = $var_code[$x] -bxor 35`, meaning the bytes were XORed with decimal 35.
8. Decoded the final Base64 layer with From Base64 followed by XOR (key 35) and found the C2 IP.

## Attack Chain Summary

```
Word document
  -> VBA macro (auto-executes on open)
    -> hidden PowerShell (Base64 encoded)
      -> Base64 -> GZIP
        -> another Base64 layer
          -> byte array var_code
            -> XOR with decimal 35
              -> C2 IP
```

## Findings

| Question | Answer |
| --- | --- |
| Type of encoding used | Base64 |
| Archive type after decoding | GZIP |
| Byte array with the obfuscation applied | `var_code` |
| Decimal XOR value | 35 |
| C2 IP address | `176.103.56[.]89` (defanged) |

## MITRE ATT&CK Mapping

- T1566.001: Phishing, Spearphishing Attachment
- T1204.002: User Execution, Malicious File
- T1059.005: Command and Scripting Interpreter, Visual Basic
- T1059.001: Command and Scripting Interpreter, PowerShell
- T1027: Obfuscated Files or Information
- T1140: Deobfuscate/Decode Files or Information

## What I Learned

Most malware does not use Hollywood-level encryption. Attackers often stack simple techniques like Base64, compression, PowerShell, XOR and string splitting, and that layering makes the payload hard to read at first. The biggest lesson for me was to not stop at the first suspicious command, and to keep following the layers until I understand what the payload does or contacts.

## Resources

- [CyberChef](https://gchq.github.io/CyberChef/)
- [oletools / olevba](https://github.com/decalage2/oletools)
- Blue Team Labs Online, Macro-ni lab
- Microsoft PowerShell `-EncodedCommand` documentation
