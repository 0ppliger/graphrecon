from pyrate_limiter import Rate, Limiter


class RateLimiter(Limiter):
    def __init__(self, batch: int, delay: int):
        if batch < 1:
            raise ValueError(
                "rate limiter's batch size must be greather than 0")

        if delay < 0:
            raise ValueError(
                "rate limiter's delay must be greather or equal to 0")

        super().__init__(Rate(batch, delay))
