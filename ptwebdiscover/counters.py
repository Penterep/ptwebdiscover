import time
import datetime
from ptlibs import ptmisclib

class Counters:

    keyspace = 0                                #keyspace for one directory (static value calculated on start by prepare_payloads)
    keyspace_complete = 0                       #total keyspace to complete

    start_time = time.time()
    counter = 0                                 #counter for realized request in current directory
    counter_complete = 0                        #counter for realized request total
    directory_finished = 0                      #counter for finished directories

    actual_directory = ""                       #current directory name
    actual_directory_not_found_status = None    #status code for not found in current directory
    non_existing_domain_status = None           #status code for non existing domain (subdomain)
    non_existing_domain_title = None            #title for non existing domain (subdomain)
    non_existing_domain_redirect = None         #is redirect for non existing domain (subdomain)

    @classmethod
    def set_keyspace(self, value: int) -> None:
        self.keyspace = value

    @classmethod
    def get_keyspace(self) -> int:
        return self.keyspace

    @classmethod
    def increment_keyspace_complete(self) -> None:
        self.keyspace_complete += 1

    @classmethod
    def increment_keyspace_complete_by(self, increment: int) -> None:
        self.keyspace_complete += increment

    @classmethod
    def set_keyspace_complete(self, value: int = 0) -> None:
        self.keyspace_complete = value

    @classmethod
    def get_keyspace_complete(self) -> int:
        return self.keyspace_complete

    @classmethod
    def get_counter(self) -> int:
        return self.counter
    
    @classmethod
    def reset_counter(self) -> None:
        self.counter = 0

    @classmethod
    def increment_counter(self) -> None:
        self.counter += 1

    @classmethod
    def reset_counter_complete(self) -> None:
        self.counter_complete = 0

    @classmethod
    def increment_counter_complete(self) -> None:
        self.counter_complete += 1

    @classmethod
    def set_start_time(self) -> None:
        self.start_time = time.time()

    @classmethod
    def get_elapsed_time(self) -> float:
        return ptmisclib.time2str(time.time() - self.start_time)
    
    @classmethod
    def get_time_to_finish(self) -> str:
        if self.counter == 0 or self.counter_complete == 0:
            time_to_finish_complete = 0
        else:
            time_to_finish_complete = int(((time.time() - self.start_time) / self.counter_complete) * (self.keyspace_complete - self.counter_complete))
        return str(datetime.timedelta(seconds=time_to_finish_complete))

    @classmethod
    def get_progress_percentage(self) -> int:
        if self.keyspace == 0:
            return 0
        percentage = int(self.counter / self.keyspace * 100)
        return percentage if percentage <= 100 else 100
    
    @classmethod
    def get_progress_complete_percentage(self) -> int:
        if self.keyspace_complete == 0:
            return 0
        percentage = int(self.counter_complete / self.keyspace_complete * 100)
        return percentage if percentage <= 100 else 100
    
    @classmethod
    def set_actual_directory(self, name: str) -> None:
        self.actual_directory = name

    @classmethod
    def get_actual_directory(self, add_slash_to_end: bool = False) -> str:
        if add_slash_to_end and not self.actual_directory.endswith("/"):
            return self.actual_directory + "/"
        return self.actual_directory
    
    @classmethod
    def set_actual_directory_not_found_status(self, status: int) -> None:
        self.actual_directory_not_found_status = status

    @classmethod
    def get_actual_directory_not_found_status(self) -> int:
        return self.actual_directory_not_found_status
    
    @classmethod
    def reset_directory_finished(self) -> None:
        self.directory_finished = 0

    @classmethod
    def increment_directory_finished(self) -> None:
        self.directory_finished += 1

    @classmethod
    def get_directory_finished(self) -> int:
        return self.directory_finished