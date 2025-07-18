import os, sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators


@Configuration()
class GeneratingCSC(GeneratingCommand):
    """
    The generatingcsc command generates a specific number of records.

    Example:

    ``| generatingcsc count=4``

    Returns a 4 records having text 'Test Event'.
    """

    count = Option(require=True, validate=validators.Integer(0))

    def generate(self):

        # To connect with Splunk, use the instantiated service object which is created using the server-uri and
        # other meta details and can be accessed as shown below
        # Example:-
        #    service = self.service
        #    info = service.info //access the Splunk Server info

        self.logger.debug("Generating %s events" % self.count)
        for i in range(1, self.count + 1):
            text = f'Test Event {i}'
            yield {'_time': time.time(), 'event_no': i, '_raw': text}


dispatch(GeneratingCSC, sys.argv, sys.stdin, sys.stdout, __name__)