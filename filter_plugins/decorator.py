
from functools import wraps
import syslog
import time


class CloudRetry(object):
    """ CloudRetry can be used by any cloud provider, in order to implement a
        backoff algorithm/retry effect based on Status Code from Exceptions.
    """
    # This is the base class of the exception.
    # AWS Example botocore.exceptions.ClientError
    base_class = None

    @staticmethod
    def status_code_from_exception(error):
        """ Return the status code from the exception object
        Args:
            error (object): The exception itself.
        """
        pass

    @staticmethod
    def found(response_code):
        """ Return True if the Response Code to retry on was found.
        Args:
            response_code (str): This is the Response Code that is being matched against.
        """
        pass

    @classmethod
    def backoff(cls, tries=10, delay=3, backoff=2):
        """ Retry calling the Cloud decorated function using an exponential backoff.
        Kwargs:
            tries (int): Number of times to try (not retry) before giving up
                default=10
            delay (int): Initial delay between retries in seconds
                default=3
            backoff (int): backoff multiplier e.g. value of 2 will double the delay each retry
                default=2

        """
        def deco(f):
            @wraps(f)
            def retry_func(*args, **kwargs):
                max_tries, max_delay = tries, delay
                while max_tries > 1:
                    try:
                        return f(*args, **kwargs)
                    except Exception as e:
                        if isinstance(e, cls.base_class):
                            response_code = cls.status_code_from_exception(e)
                            if cls.found(response_code):
                                msg = "{0}: Retrying in {1} seconds...".format(str(e), max_delay)
                                syslog.syslog(syslog.LOG_INFO, msg)
                                time.sleep(max_delay)
                                max_tries -= 1
                                max_delay *= backoff
                            else:
                                # Return original exception if exception is not a ClientError
                                raise e
                        else:
                            # Return original exception if exception is not a ClientError
                            raise e
                return f(*args, **kwargs)

            return retry_func  # true decorator

        return deco
