/* dh.c - SharedSecret project.

   Copyright (C) 2004 - Arvydas Juskaitis <arvydasj@users.sourceforge.net>

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2, or (at your option) any
   later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
*/

#include <openssl/bn.h>
#include <stdlib.h>
#include "defs.h"


/*
 * Prime (768 bits):
 * FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
 * 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
 * EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
 * E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF
 * The base (generator) has value 2.
 */
char dh_group_768[] = "\x00"
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2"
	"\x21\x68\xC2\x34\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1"
	"\x29\x02\x4E\x08\x8A\x67\xCC\x74\x02\x0B\xBE\xA6"
	"\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD"
	"\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D"
	"\xF2\x5F\x14\x37\x4F\xE1\x35\x6D\x6D\x51\xC2\x45"
	"\xE4\x85\xB5\x76\x62\x5E\x7E\xC6\xF4\x4C\x42\xE9"
	"\xA6\x3A\x36\x20\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

/*
 * Prime (1024 bits):
 * FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
 * 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
 * EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
 * E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
 * EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
 * FFFFFFFF FFFFFFFF
 * The base (generator) has value 2.
 */
unsigned char dh_group_1024[] = "\x00"
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2"
	"\x21\x68\xC2\x34\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1"
	"\x29\x02\x4E\x08\x8A\x67\xCC\x74\x02\x0B\xBE\xA6"
	"\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD"
	"\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D"
	"\xF2\x5F\x14\x37\x4F\xE1\x35\x6D\x6D\x51\xC2\x45"
	"\xE4\x85\xB5\x76\x62\x5E\x7E\xC6\xF4\x4C\x42\xE9"
	"\xA6\x37\xED\x6B\x0B\xFF\x5C\xB6\xF4\x06\xB7\xED"
	"\xEE\x38\x6B\xFB\x5A\x89\x9F\xA5\xAE\x9F\x24\x11"
	"\x7C\x4B\x1F\xE6\x49\x28\x66\x51\xEC\xE6\x53\x81"
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

/*
 * Prime (1536 bits):
 * FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
 * 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
 * EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
 * E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
 * EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
 * C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
 * 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
 * 670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF 
 * The base (generator) has value 2.
 */
unsigned char dh_group_1536[] = "\x00"
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2"
	"\x21\x68\xC2\x34\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1"
	"\x29\x02\x4E\x08\x8A\x67\xCC\x74\x02\x0B\xBE\xA6"
	"\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD"
	"\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D"
	"\xF2\x5F\x14\x37\x4F\xE1\x35\x6D\x6D\x51\xC2\x45"
	"\xE4\x85\xB5\x76\x62\x5E\x7E\xC6\xF4\x4C\x42\xE9"
	"\xA6\x37\xED\x6B\x0B\xFF\x5C\xB6\xF4\x06\xB7\xED"
	"\xEE\x38\x6B\xFB\x5A\x89\x9F\xA5\xAE\x9F\x24\x11"
	"\x7C\x4B\x1F\xE6\x49\x28\x66\x51\xEC\xE4\x5B\x3D"
	"\xC2\x00\x7C\xB8\xA1\x63\xBF\x05\x98\xDA\x48\x36"
	"\x1C\x55\xD3\x9A\x69\x16\x3F\xA8\xFD\x24\xCF\x5F"
	"\x83\x65\x5D\x23\xDC\xA3\xAD\x96\x1C\x62\xF3\x56"
	"\x20\x85\x52\xBB\x9E\xD5\x29\x07\x70\x96\x96\x6D"
	"\x67\x0C\x35\x4E\x4A\xBC\x98\x04\xF1\x74\x6C\x08"
	"\xCA\x23\x73\x27\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

/*
 * Prime (2048 bits):
 * FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
 * 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
 * EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
 * E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
 * EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
 * C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
 * 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
 * 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
 * E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
 * DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
 * 15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
 * The base (generator) has value 2.
 */
unsigned char dh_group_2048[] = "\x00"
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2"
	"\x21\x68\xC2\x34\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1"
	"\x29\x02\x4E\x08\x8A\x67\xCC\x74\x02\x0B\xBE\xA6"
	"\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD"
	"\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D"
	"\xF2\x5F\x14\x37\x4F\xE1\x35\x6D\x6D\x51\xC2\x45"
	"\xE4\x85\xB5\x76\x62\x5E\x7E\xC6\xF4\x4C\x42\xE9"
	"\xA6\x37\xED\x6B\x0B\xFF\x5C\xB6\xF4\x06\xB7\xED"
	"\xEE\x38\x6B\xFB\x5A\x89\x9F\xA5\xAE\x9F\x24\x11"
	"\x7C\x4B\x1F\xE6\x49\x28\x66\x51\xEC\xE4\x5B\x3D"
	"\xC2\x00\x7C\xB8\xA1\x63\xBF\x05\x98\xDA\x48\x36"
	"\x1C\x55\xD3\x9A\x69\x16\x3F\xA8\xFD\x24\xCF\x5F"
	"\x83\x65\x5D\x23\xDC\xA3\xAD\x96\x1C\x62\xF3\x56"
	"\x20\x85\x52\xBB\x9E\xD5\x29\x07\x70\x96\x96\x6D"
	"\x67\x0C\x35\x4E\x4A\xBC\x98\x04\xF1\x74\x6C\x08"
	"\xCA\x18\x21\x7C\x32\x90\x5E\x46\x2E\x36\xCE\x3B"
	"\xE3\x9E\x77\x2C\x18\x0E\x86\x03\x9B\x27\x83\xA2"
	"\xEC\x07\xA2\x8F\xB5\xC5\x5D\xF0\x6F\x4C\x52\xC9"
	"\xDE\x2B\xCB\xF6\x95\x58\x17\x18\x39\x95\x49\x7C"
	"\xEA\x95\x6A\xE5\x15\xD2\x26\x18\x98\xFA\x05\x10"
	"\x15\x72\x8E\x5A\x8A\xAC\xAA\x68\xFF\xFF\xFF\xFF"
	"\xFF\xFF\xFF\xFF";

/*
 * Prime (3072 bits):
 * FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
 * 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
 * EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
 * E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
 * EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
 * C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
 * 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
 * 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
 * E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
 * DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
 * 15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
 * ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
 * ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
 * F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
 * BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
 * 43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
 * The base (generator) has value 2.
 */
unsigned char dh_group_3072[] = "\x00"
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2"
	"\x21\x68\xC2\x34\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1"
	"\x29\x02\x4E\x08\x8A\x67\xCC\x74\x02\x0B\xBE\xA6"
	"\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD"
	"\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D"
	"\xF2\x5F\x14\x37\x4F\xE1\x35\x6D\x6D\x51\xC2\x45"
	"\xE4\x85\xB5\x76\x62\x5E\x7E\xC6\xF4\x4C\x42\xE9"
	"\xA6\x37\xED\x6B\x0B\xFF\x5C\xB6\xF4\x06\xB7\xED"
	"\xEE\x38\x6B\xFB\x5A\x89\x9F\xA5\xAE\x9F\x24\x11"
	"\x7C\x4B\x1F\xE6\x49\x28\x66\x51\xEC\xE4\x5B\x3D"
	"\xC2\x00\x7C\xB8\xA1\x63\xBF\x05\x98\xDA\x48\x36"
	"\x1C\x55\xD3\x9A\x69\x16\x3F\xA8\xFD\x24\xCF\x5F"
	"\x83\x65\x5D\x23\xDC\xA3\xAD\x96\x1C\x62\xF3\x56"
	"\x20\x85\x52\xBB\x9E\xD5\x29\x07\x70\x96\x96\x6D"
	"\x67\x0C\x35\x4E\x4A\xBC\x98\x04\xF1\x74\x6C\x08"
	"\xCA\x18\x21\x7C\x32\x90\x5E\x46\x2E\x36\xCE\x3B"
	"\xE3\x9E\x77\x2C\x18\x0E\x86\x03\x9B\x27\x83\xA2"
	"\xEC\x07\xA2\x8F\xB5\xC5\x5D\xF0\x6F\x4C\x52\xC9"
	"\xDE\x2B\xCB\xF6\x95\x58\x17\x18\x39\x95\x49\x7C"
	"\xEA\x95\x6A\xE5\x15\xD2\x26\x18\x98\xFA\x05\x10"
	"\x15\x72\x8E\x5A\x8A\xAA\xC4\x2D\xAD\x33\x17\x0D"
	"\x04\x50\x7A\x33\xA8\x55\x21\xAB\xDF\x1C\xBA\x64"
	"\xEC\xFB\x85\x04\x58\xDB\xEF\x0A\x8A\xEA\x71\x57"
	"\x5D\x06\x0C\x7D\xB3\x97\x0F\x85\xA6\xE1\xE4\xC7"
	"\xAB\xF5\xAE\x8C\xDB\x09\x33\xD7\x1E\x8C\x94\xE0"
	"\x4A\x25\x61\x9D\xCE\xE3\xD2\x26\x1A\xD2\xEE\x6B"
	"\xF1\x2F\xFA\x06\xD9\x8A\x08\x64\xD8\x76\x02\x73"
	"\x3E\xC8\x6A\x64\x52\x1F\x2B\x18\x17\x7B\x20\x0C"
	"\xBB\xE1\x17\x57\x7A\x61\x5D\x6C\x77\x09\x88\xC0"
	"\xBA\xD9\x46\xE2\x08\xE2\x4F\xA0\x74\xE5\xAB\x31"
	"\x43\xDB\x5B\xFC\xE0\xFD\x10\x8E\x4B\x82\xD1\x20"
	"\xA9\x3A\xD2\xCA\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

/*
 * Prime (4096 bits):
 * FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
 * 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
 * EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
 * E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
 * EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
 * C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
 * 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
 * 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
 * E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
 * DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
 * 15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
 * ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
 * ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
 * F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
 * BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
 * 43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
 * 88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
 * 2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
 * 287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
 * 1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
 * 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
 * FFFFFFFF FFFFFFFF
 * The base (generator) has value 2.
 */
unsigned char dh_group_4096[] = "\x00"
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2"
	"\x21\x68\xC2\x34\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1"
	"\x29\x02\x4E\x08\x8A\x67\xCC\x74\x02\x0B\xBE\xA6"
	"\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD"
	"\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D"
	"\xF2\x5F\x14\x37\x4F\xE1\x35\x6D\x6D\x51\xC2\x45"
	"\xE4\x85\xB5\x76\x62\x5E\x7E\xC6\xF4\x4C\x42\xE9"
	"\xA6\x37\xED\x6B\x0B\xFF\x5C\xB6\xF4\x06\xB7\xED"
	"\xEE\x38\x6B\xFB\x5A\x89\x9F\xA5\xAE\x9F\x24\x11"
	"\x7C\x4B\x1F\xE6\x49\x28\x66\x51\xEC\xE4\x5B\x3D"
	"\xC2\x00\x7C\xB8\xA1\x63\xBF\x05\x98\xDA\x48\x36"
	"\x1C\x55\xD3\x9A\x69\x16\x3F\xA8\xFD\x24\xCF\x5F"
	"\x83\x65\x5D\x23\xDC\xA3\xAD\x96\x1C\x62\xF3\x56"
	"\x20\x85\x52\xBB\x9E\xD5\x29\x07\x70\x96\x96\x6D"
	"\x67\x0C\x35\x4E\x4A\xBC\x98\x04\xF1\x74\x6C\x08"
	"\xCA\x18\x21\x7C\x32\x90\x5E\x46\x2E\x36\xCE\x3B"
	"\xE3\x9E\x77\x2C\x18\x0E\x86\x03\x9B\x27\x83\xA2"
	"\xEC\x07\xA2\x8F\xB5\xC5\x5D\xF0\x6F\x4C\x52\xC9"
	"\xDE\x2B\xCB\xF6\x95\x58\x17\x18\x39\x95\x49\x7C"
	"\xEA\x95\x6A\xE5\x15\xD2\x26\x18\x98\xFA\x05\x10"
	"\x15\x72\x8E\x5A\x8A\xAA\xC4\x2D\xAD\x33\x17\x0D"
	"\x04\x50\x7A\x33\xA8\x55\x21\xAB\xDF\x1C\xBA\x64"
	"\xEC\xFB\x85\x04\x58\xDB\xEF\x0A\x8A\xEA\x71\x57"
	"\x5D\x06\x0C\x7D\xB3\x97\x0F\x85\xA6\xE1\xE4\xC7"
	"\xAB\xF5\xAE\x8C\xDB\x09\x33\xD7\x1E\x8C\x94\xE0"
	"\x4A\x25\x61\x9D\xCE\xE3\xD2\x26\x1A\xD2\xEE\x6B"
	"\xF1\x2F\xFA\x06\xD9\x8A\x08\x64\xD8\x76\x02\x73"
	"\x3E\xC8\x6A\x64\x52\x1F\x2B\x18\x17\x7B\x20\x0C"
	"\xBB\xE1\x17\x57\x7A\x61\x5D\x6C\x77\x09\x88\xC0"
	"\xBA\xD9\x46\xE2\x08\xE2\x4F\xA0\x74\xE5\xAB\x31"
	"\x43\xDB\x5B\xFC\xE0\xFD\x10\x8E\x4B\x82\xD1\x20"
	"\xA9\x21\x08\x01\x1A\x72\x3C\x12\xA7\x87\xE6\xD7"
	"\x88\x71\x9A\x10\xBD\xBA\x5B\x26\x99\xC3\x27\x18"
	"\x6A\xF4\xE2\x3C\x1A\x94\x68\x34\xB6\x15\x0B\xDA"
	"\x25\x83\xE9\xCA\x2A\xD4\x4C\xE8\xDB\xBB\xC2\xDB"
	"\x04\xDE\x8E\xF9\x2E\x8E\xFC\x14\x1F\xBE\xCA\xA6"
	"\x28\x7C\x59\x47\x4E\x6B\xC0\x5D\x99\xB2\x96\x4F"
	"\xA0\x90\xC3\xA2\x23\x3B\xA1\x86\x51\x5B\xE7\xED"
	"\x1F\x61\x29\x70\xCE\xE2\xD7\xAF\xB8\x1B\xDD\x76"
	"\x21\x70\x48\x1C\xD0\x06\x91\x27\xD5\xB0\x5A\xA9"
	"\x93\xB4\xEA\x98\x8D\x8F\xDD\xC1\x86\xFF\xB7\xDC"
	"\x90\xA6\xC0\x8F\x4D\xF4\x35\xC9\x34\x06\x31\x99"
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";


int dh_init_group_params(int dh_group, BIGNUM** pbn_prime, BIGNUM** pbn_base) 
{
	int	err, size;
	unsigned char*	ptr;
	
	/* allocate BNs */
	*pbn_base = BN_new();
	if (!*pbn_base) {
		err = ERR_INTERNAL;
		goto ret_err;
	}

	switch (dh_group) {
	case DH_GROUP_768:
		ptr = dh_group_768;
		size = sizeof(dh_group_768);
		break;

	case DH_GROUP_1024:
		ptr = dh_group_1024;
		size = sizeof(dh_group_1024);
		break;

	case DH_GROUP_1536:
		ptr = dh_group_1536;
		size = sizeof(dh_group_1536);
		break;

	case DH_GROUP_2048:
		ptr = dh_group_2048;
		size = sizeof(dh_group_2048);
		break;

	case DH_GROUP_3072:
		ptr = dh_group_3072;
		size = sizeof(dh_group_3072);
		break;

	case DH_GROUP_4096:
		ptr = dh_group_4096;
		size = sizeof(dh_group_4096);
		break;

	default:
		err = ERR_INVALID_PARAM;
		goto ret_err;
	}

	/* fn allocates BN for us */
	*pbn_prime = BN_bin2bn(ptr, size, NULL);
	if (!*pbn_prime) {
		err = ERR_INTERNAL;
		goto ret_err;
	}

	/* we have base value 2 everywhere */
	if (!BN_set_word(*pbn_base, 2)) {
		err = ERR_INTERNAL;
		goto ret_err;
	}

	return ERR_SUCCESS;

 ret_err:;
	if (*pbn_prime)
		BN_free(*pbn_prime);
		
	if (*pbn_base) 
		BN_free(*pbn_base);

	*pbn_prime = NULL;
	*pbn_base = NULL;

	return err;
}

int dh_gen_private_public(int dh_group, BIGNUM* bn_prime, BIGNUM* bn_base,
	BIGNUM** pbn_private, unsigned char** ppublic, int* ppublic_len)
{
	int		err, len;
	BN_CTX*	ctx = NULL;
	BIGNUM*	bn_public = NULL;
	
	*pbn_private = NULL;
	*ppublic = NULL;

	/* allocate BNs */
	*pbn_private = BN_new();
	if (!*pbn_private) {
		err = ERR_INTERNAL;
		goto ret_err;
	}

	bn_public = BN_new();
	if (!bn_public) {
		err = ERR_INTERNAL;
		goto ret_err;
	}

	ctx = BN_CTX_new();
	if (!ctx) {
		err = ERR_INTERNAL;
		goto ret_err;
	}
	
	/* private key */
	if (!BN_rand(*pbn_private, dh_group, 1, 1)) {
		err = ERR_INTERNAL;
		goto ret_err;
	}

	/*  public key */
	if (!BN_mod_exp(bn_public, bn_base, *pbn_private, bn_prime, ctx)){
		err = ERR_INTERNAL;
		goto ret_err;
	}

	/* get binary */
	*ppublic_len = BN_num_bytes(bn_public);
	*ppublic = (unsigned char*)malloc(*ppublic_len);
	if (!*ppublic) {
		err = ERR_INTERNAL;
		goto ret_err;
	}

	len = BN_bn2bin(bn_public, *ppublic);
	if (len != *ppublic_len) {
		err = ERR_INTERNAL;
		goto ret_err;
	}
	
	BN_free(bn_public);
	BN_CTX_free(ctx);

	return ERR_SUCCESS;

 ret_err:;
	if (*pbn_private)
		BN_free(*pbn_private);
		
	if (bn_public) 
		BN_free(bn_public);

	if (ctx)
		BN_CTX_free(ctx);
	
	*pbn_private = NULL;
	*ppublic = NULL;

	return err;
}

int dh_get_secret(const unsigned char* public, short public_len,
	BIGNUM* bn_private, BIGNUM* bn_prime, unsigned char** psecret_key,
	int* psecret_key_len)
{
	int		err, len;
	BIGNUM*	bn_public = NULL;
	BIGNUM*	bn_secret = NULL;
	BN_CTX*	ctx = NULL;
	
	*psecret_key = NULL;

	/* allocate BNs */
	bn_public = BN_bin2bn(public, public_len, NULL);
	if (!bn_public) {
		err = ERR_INTERNAL;
		goto ret_err;
	}
	
	bn_secret = BN_new();
	if (!bn_secret) {
		err = ERR_INTERNAL;
		goto ret_err;
	}

	ctx = BN_CTX_new();
	if (!ctx) {
		err = ERR_INTERNAL;
		goto ret_err;
	}
	
	/* secret */
	if (!BN_mod_exp(bn_secret, bn_public, bn_private, bn_prime, ctx)) {
		err = ERR_INTERNAL;
		goto ret_err;
	}

	/* get binary */
	*psecret_key_len = BN_num_bytes(bn_secret);
	*psecret_key = (unsigned char*)malloc(*psecret_key_len);
	if (!*psecret_key) {
		err = ERR_INTERNAL;
		goto ret_err;
	}

	len = BN_bn2bin(bn_secret, *psecret_key);
	if (len != *psecret_key_len) {
		err = ERR_INTERNAL;
		goto ret_err;
	}
	
	BN_free(bn_public);
	BN_free(bn_secret);
	BN_CTX_free(ctx);

	return ERR_SUCCESS;

 ret_err:;
	if (*psecret_key)
		free(*psecret_key);

	if (bn_public)
		BN_free(bn_public);

	if (bn_secret)
		BN_free(bn_secret);

	if (ctx)
		BN_CTX_free(ctx);
	
	*psecret_key = NULL;

	return err;
}



