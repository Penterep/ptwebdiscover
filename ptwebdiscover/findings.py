from ptlibs.threads.arraylock import ThreadSafeArray

from ptdataclasses.findingdetail import FindingDetail


class Findings:
    findings = ThreadSafeArray[str]()
    findings2 = ThreadSafeArray[str]()
    details = ThreadSafeArray[FindingDetail]()
    directories = ThreadSafeArray[str]()
    technologies = ThreadSafeArray[str]()
    visited = ThreadSafeArray[str]()