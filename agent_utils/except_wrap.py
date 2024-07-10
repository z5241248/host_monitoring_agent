import functools


def catch_except(default=None):
    def wrap(fn):
        @functools.wraps(fn)
        def _fn(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                if default is not None:
                    return default
                return f'{e}'

        return _fn

    return wrap


# @catch_except('b not equal 0')
# def ca(a, b):
#     return a / b
