import os
import dnstest.params as params
import datetime
from dnstest.utils import Skip


class FakeTime:
    """Set system environment variables.
    All application started with these variables will use libfaketime.

    """
    DATE_FORMAT = "%Y-%m-%d %T"

    def __init__(self):
        if not os.path.exists(params.out_dir):
            raise Exception("Output directory doesn't exist")
        self.file_path = params.out_dir + "/faketime.conf"

    def __enter__(self):
        os.environ["LD_PRELOAD"] = params.libfaketime_path
        os.environ["FAKETIME_TIMESTAMP_FILE"] = self.file_path
        os.environ["FAKETIME_NO_CACHE"] = "1"
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.environ["LD_PRELOAD"] = ""

    def _write_string(self, string):
        with open(self.file_path, "w") as file:
            file.write(string)

    def set_fixed(self, dt):
        """Set system time and stop clock at this time.

        :type dt: datetime.datetime
        :param dt: Date and time
        """
        self._write_string(dt.strftime(self.DATE_FORMAT))

    def set_time(self, dt):
        """Set system time, time will change with configured speed.

        :type dt: datetime.datetime
        :param dt: Date and time
        """
        self._write_string("@" + dt.strftime(self.DATE_FORMAT))

    def set_speed(self, speed):
        """Set speed changing time.

        :param speed: Number how much faster time should change.
        """
        self._write_string("x{}".format(speed))

    @classmethod
    def check(cls):
        """Check if libfaketime is present in system.

        :raises Skip: if not present.
        :return: True
        """
        from subprocess import check_output, CalledProcessError
        timestamp = 1337  # just some timestamp
        dt = datetime.datetime.fromtimestamp(timestamp)
        env = os.environ.copy()
        env["LD_PRELOAD"] = params.libfaketime_path
        env["FAKETIME"] = dt.strftime(cls.DATE_FORMAT)
        try:
            if int(check_output(["date", "+%s"], env=env)) == timestamp:
                return True
        except CalledProcessError:
            raise Skip()
        raise Skip("libfaketime not detected")
