package ngrislain.fast_hash;

import static org.junit.Assert.*;
import static java.lang.System.out;
import static ngrislain.fast_hash.Hash.*;

import org.junit.Test;

public class HashTest {

	@Test
	public void test() {
		String str = "nicolas";
		byte[] data = str.getBytes();
		print(data);
		
		out.println(hash(data, 0));
		out.println(hash(str, 0));
	}

}
