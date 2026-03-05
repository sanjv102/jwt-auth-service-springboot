package com.jwt.auth.ratelimit;

import java.time.Duration;

public record RateLimitPolicy(
		int MAX_REQUESTS,
	    Duration window) 
{

}
