from pathlib import Path
from .base import ModuleTestBase


class TestUnstructured(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["unstructured", "filedownload", "httpx", "excavate", "speculate"]
    config_overrides = {"web": {"spider_distance": 2, "spider_depth": 2}}

    pdf_data = r"""%PDF-1.3
%���� ReportLab Generated PDF document http://www.reportlab.com
1 0 obj
<<
/F1 2 0 R
>>
endobj
2 0 obj
<<
/BaseFont /Helvetica /Encoding /WinAnsiEncoding /Name /F1 /Subtype /Type1 /Type /Font
>>
endobj
3 0 obj
<<
/Contents 7 0 R /MediaBox [ 0 0 595.2756 841.8898 ] /Parent 6 0 R /Resources <<
/Font 1 0 R /ProcSet [ /PDF /Text /ImageB /ImageC /ImageI ]
>> /Rotate 0 /Trans <<

>> 
  /Type /Page
>>
endobj
4 0 obj
<<
/PageMode /UseNone /Pages 6 0 R /Type /Catalog
>>
endobj
5 0 obj
<<
/Author (anonymous) /CreationDate (D:20240603185816+00'00') /Creator (ReportLab PDF Library - www.reportlab.com) /Keywords () /ModDate (D:20240603185816+00'00') /Producer (ReportLab PDF Library - www.reportlab.com) 
  /Subject (unspecified) /Title (untitled) /Trapped /False
>>
endobj
6 0 obj
<<
/Count 1 /Kids [ 3 0 R ] /Type /Pages
>>
endobj
7 0 obj
<<
/Filter [ /ASCII85Decode /FlateDecode ] /Length 107
>>
stream
GapQh0E=F,0U\H3T\pNYT^QKk?tc>IP,;W#U1^23ihPEM_?CW4KISi90MjG^2,FS#<RC5+c,n)Z;$bK$b"5I[<!^TD#gi]&=5X,[5@Y@V~>endstream
endobj
xref
0 8
0000000000 65535 f 
0000000073 00000 n 
0000000104 00000 n 
0000000211 00000 n 
0000000414 00000 n 
0000000482 00000 n 
0000000778 00000 n 
0000000837 00000 n 
trailer
<<
/ID 
[<80d9f5b964fc99284501deb7a6a637f7><80d9f5b964fc99284501deb7a6a637f7>]
% ReportLab generated PDF document -- digest (http://www.reportlab.com)

/Info 5 0 R
/Root 4 0 R
/Size 8
>>
startxref
1034
%%EOF"""

    unstructured_response = "Hello, World!"

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            dict(uri="/"),
            dict(response_data='<a href="/Test_PDF"/>'),
        )
        module_test.set_expect_requests(
            dict(uri="/Test_PDF"),
            dict(response_data=self.pdf_data, headers={"Content-Type": "application/pdf"}),
        )

    def check(self, module_test, events):
        filesystem_events = [e for e in events if e.type == "FILESYSTEM"]
        assert 1 == len(filesystem_events), filesystem_events
        filesystem_event = filesystem_events[0]
        file = Path(filesystem_event.data["path"])
        assert file.is_file(), "Destination file doesn't exist"
        assert open(file).read() == self.pdf_data, f"File at {file} does not contain the correct content"
        raw_text_events = [e for e in events if e.type == "RAW_TEXT"]
        assert 1 == len(raw_text_events), "Failed to emit RAW_TEXT event"
        assert (
            raw_text_events[0].data == self.unstructured_response
        ), f"Text extracted from PDF is incorrect, got {raw_text_events[0].data}"
