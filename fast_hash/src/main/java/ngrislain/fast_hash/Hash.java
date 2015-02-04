package ngrislain.fast_hash;

import java.io.UnsupportedEncodingException;

import org.apache.log4j.Logger;

public class Hash {
	public static final Logger LOGGER = Logger.getLogger(Hash.class);
	
	/**
	 * This is an implementation of CparWow (cf.
	 * http://floodyberry.com/noncryptohashzoo/CrapWow.html)
	 */
	public static final long LONG_LO_MASK = 0x00000000ffffffffL;

	public final static int CWOW_32_M = 0x57559429;
	public final static int CWOW_32_N = 0x5052acdb;

	public final static long CWOW_64_M = 0x95b47aa3355ba1a1L;
	public final static long CWOW_64_M_LO = CWOW_64_M & LONG_LO_MASK;
	public final static long CWOW_64_M_HI = CWOW_64_M >>> 32;

	public final static long CWOW_64_N = 0x8a970be7488fda55L;
	public final static long CWOW_64_N_LO = CWOW_64_N & LONG_LO_MASK;
	public final static long CWOW_64_N_HI = CWOW_64_N >>> 32;

	/** perform unsigned extension of int to long */
	public static final long uintToLong(int i) {
		long l = (long) i;
		return (l << 32) >>> 32;
	}

	/** get an int from the specified index into the byte array */
	public static final int getInt(byte[] data, int index) {
		int i = data[index] & 0xff;
		i |= (data[++index] & 0xff) << 8;
		i |= (data[++index] & 0xff) << 16;
		i |= (data[++index] << 24);
		return i;
	}

	/**
	 * get a partial int from the specified index using the specified number of
	 * bytes into the byte array
	 */
	public static final int getPartInt(byte[] data, int index, int available) {
		int i = data[index] & 0xff;
		if (available > 1) {
			i |= (data[++index] & 0xff) << 8;
			if (available > 2) {
				i |= (data[++index] & 0xff) << 16;
			}
		}
		return i;
	}

	/**
	 * gather a partial long from the specified index using the specified number
	 * of bytes into the byte array
	 */
	public static final long getPartLong(byte[] data, int index, int available) {
		if (available >= 4) {
			int i = getInt(data, index);
			long l = uintToLong(i);
			available -= 4;
			if (available == 0) {
				return l;
			}
			int i2 = getPartInt(data, index + 4, available);
			l <<= (available << 3);
			l |= (long) i2;
			return l;
		}
		return (long) getPartInt(data, index, available);
	}
	
	/**
	 * Implementation of CrapWow Hash, ported from 64-bit version.
	 */
	public static final long hash(byte[] data, long seed) {
		final int length = data.length;
		/* cwfold( a, b, lo, hi ): */
		/* p = (u64)(a) * (u128)(b); lo ^=(u64)p; hi ^= (u64)(p >> 64) */
		/* cwmixa( in ): cwfold( in, m, k, h ) */
		/* cwmixb( in ): cwfold( in, n, h, k ) */

		long hVal = seed;
		long k = length + seed + CWOW_64_N;
		int pos = 0;
		int len = length;
		long aL, aH, bL, bH;
		long r1, r2, r3, rML;
		long pL;
		long pH;
		while (len >= 16) {
			/* cwmixb(X) = cwfold( X, N, hVal, k ) */
			aL = getInt(data, pos) & LONG_LO_MASK;
			pos += 4;
			aH = getInt(data, pos) & LONG_LO_MASK;
			pos += 4;
			bL = CWOW_64_N_LO;
			bH = CWOW_64_N_HI;
			r1 = aL * bL;
			r2 = aH * bL;
			r3 = aL * bH;
			rML = (r1 >>> 32) + (r2 & LONG_LO_MASK) + (r3 & LONG_LO_MASK);
			pL = (r1 & LONG_LO_MASK) + ((rML & LONG_LO_MASK) << 32);
			pH = (aH * bH) + (rML >>> 32);
			hVal ^= pL;
			k ^= pH;
			/* cwmixa(Y) = cwfold( Y, M, k, hVal ) */
			aL = getInt(data, pos) & LONG_LO_MASK;
			pos += 4;
			aH = getInt(data, pos) & LONG_LO_MASK;
			pos += 4;
			bL = CWOW_64_M_LO;
			bH = CWOW_64_M_HI;
			r1 = aL * bL;
			r2 = aH * bL;
			r3 = aL * bH;
			rML = (r1 >>> 32) + (r2 & LONG_LO_MASK) + (r3 & LONG_LO_MASK);
			pL = (r1 & LONG_LO_MASK) + ((rML & LONG_LO_MASK) << 32);
			pH = (aH * bH) + (rML >>> 32);
			k ^= pL;
			hVal ^= pH;
			len -= 16;
		}
		if (len >= 8) {
			/* cwmixb(X) = cwfold( X, N, hVal, k ) */
			aL = getInt(data, pos) & LONG_LO_MASK;
			pos += 4;
			aH = getInt(data, pos) & LONG_LO_MASK;
			pos += 4;
			bL = CWOW_64_N_LO;
			bH = CWOW_64_N_HI;
			r1 = aL * bL;
			r2 = aH * bL;
			r3 = aL * bH;
			rML = (r1 >>> 32) + (r2 & LONG_LO_MASK) + (r3 & LONG_LO_MASK);
			pL = (r1 & LONG_LO_MASK) + ((rML & LONG_LO_MASK) << 32);
			pH = (aH * bH) + (rML >>> 32);
			hVal ^= pL;
			k ^= pH;
			len -= 8;
		}
		if (len > 0) {
			aL = getPartLong(data, pos, len);
			aH = aL >> 32;
			aL = aL & LONG_LO_MASK;
			/* cwmixa(Y) = cwfold( Y, M, k, hVal ) */
			bL = CWOW_64_M_LO;
			bH = CWOW_64_M_HI;
			r1 = aL * bL;
			r2 = aH * bL;
			r3 = aL * bH;
			rML = (r1 >>> 32) + (r2 & LONG_LO_MASK) + (r3 & LONG_LO_MASK);
			pL = (r1 & LONG_LO_MASK) + ((rML & LONG_LO_MASK) << 32);
			pH = (aH * bH) + (rML >>> 32);
			k ^= pL;
			hVal ^= pH;
		}
		/* cwmixb(X) = cwfold( X, N, hVal, k ) */
		aL = (hVal ^ (k + CWOW_64_N));
		aH = aL >> 32;
		aL = aL & LONG_LO_MASK;
		bL = CWOW_64_N_LO;
		bH = CWOW_64_N_HI;
		r1 = aL * bL;
		r2 = aH * bL;
		r3 = aL * bH;
		rML = (r1 >>> 32) + (r2 & LONG_LO_MASK) + (r3 & LONG_LO_MASK);
		pL = (r1 & LONG_LO_MASK) + ((rML & LONG_LO_MASK) << 32);
		pH = (aH * bH) + (rML >>> 32);
		hVal ^= pL;
		k ^= pH;
		hVal ^= k;
		return hVal;
	}
	
	/**
	 * hashes for other types
	 */
	public static final long hash(String data, long seed) {
		try {
			return hash(data.getBytes("UTF-8"), seed);
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("UTF-8 not supported", e);
			return Const.DEF_LONG;
		}
	}
	
	/**
	 * print bytes
	 */
	public static void print(byte[] data) {
		for (byte val : data) {
			System.out.print(Integer.toHexString(val)+" ");
		}
		System.out.println();
	}
}
