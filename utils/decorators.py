import os
import timeit

from loguru import logger

from . import misc


def timed(method):
    def timer(*args, **kw):
        start_time = timeit.default_timer()
        result = method(*args, **kw)
        time_taken = timeit.default_timer() - start_time
        try:
            logger.info(f"{method.__name__!r} from {os.path.basename(method.__code__.co_filename)!r} "
                        f"finished in {misc.seconds_to_string(time_taken)}")
        except Exception:
            logger.exception("Exception while tracking time taken to run function: ")
        return result

    return timer
