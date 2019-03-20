#include <iostream>
#include <stdint.h>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <cstring>
#include <string>
#include <set>
#include <map>
#include <vector>
#include <sstream>
#include <cstdio>
#include <iomanip>

using namespace std;

int read;

enum ERRORS{WRONG_FLAGS,
			NO_KEY_FILE,
			NO_OPTION_FILE,
			CANNOT_OPEN_KEY_FILE,
			INVALID_KEY,
			CANNOT_OPEN_INPUT_FILE,
			CANNOT_OPEN_OUTPUT_FILE,
			EMPTY_INPUT,
			IV_FILE_IS_NOT_NEEDED,
			WRONG_INPUT,
			WRONG_IV,
			EMPTY_IV
		   };

vector<uint8_t> Add_mod_32(vector<uint8_t> first, vector<uint8_t> second){
	vector<uint8_t> result(4);
	unsigned int sum = 0;
	for(int i=3; i>=0; i--){
		sum = (sum >> 8) + first[i] + second[i];		
		result[i] = sum & 0xff;
	}
	return result;	
}

vector<uint8_t> Add_mod_2(vector<uint8_t> first,vector<uint8_t> second){
	vector<uint8_t> result(4);
	for (int i=0; i<4; i++){
		result[i] = first[i]^second[i];
	}
	return result;
}

vector<uint8_t> t(vector<uint8_t> block){
	unsigned char Pi[8][16]={ {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2},
 						  	  {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
 						  	  {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
						  	  {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
						  	  {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
						  	  {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
						  	  {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
						  	  {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1} 
							};
	vector<uint8_t> result(4);							
	uint8_t first, second;
	for (int i=0; i<4; i++){
		first = (block[i] & 0xf0) >> 4;
		second = block[i] & 0x0f;
		first = Pi[i*2][first];
		second = Pi[i*2+1][second];
		result[i] = (first << 4) | second;
	}
	return result;
}

vector< vector<uint8_t> > Make_keys(vector<uint8_t> key){
	vector< vector<uint8_t> > it_key(32,vector<uint8_t>(4));
	for(int i=0; i<24; i++){
		copy(key.begin()+(i%8)*4, key.begin()+(i%8)*4+4, it_key[i].begin());
	}
	for(int i=24; i<32; i++){
		copy(key.begin()+(7-(i%8))*4,key.begin()+(7-(i%8))*4+4,it_key[i].begin());
	}
	return it_key;
}

vector<uint8_t> CShift_11_left(vector<uint8_t> block){
	uint32_t tmp = 0;
	vector<uint8_t> result(4);
	for(int i=0; i<4; i++){
		tmp = (tmp << 8) + block[i];
	}
	tmp = (tmp << 11) | (tmp >> 21);
	for(int i=0; i<4; i++){
		result[i] = tmp >> (24 - i*8);
	}
	return result;
}

vector<uint8_t> g(vector<uint8_t> block, vector<uint8_t> key){
	vector<uint8_t> result(4);	
	result = Add_mod_32(block, key);
	result = t(result);
	result = CShift_11_left(result);
	return result;
}

vector<uint8_t> G(vector<uint8_t> block64, vector<uint8_t> key){
	vector<uint8_t> block_l(4);
	vector<uint8_t> block_r(4);
	for(int i=0; i<4; i++){
		block_l[i] = block64[i];
		block_r[i] = block64[i+4];
	}
	vector<uint8_t> tmp(4);
	tmp = g(block_r,key);
	tmp = Add_mod_2(tmp,block_l);
	vector<uint8_t> res_l(4);
	vector<uint8_t> res_r(4);	
	for(int i=0; i<4; i++){
		res_l[i] = block_r[i];
		res_r[i] = tmp[i];
	}
	vector<uint8_t> result(4*2);
	for(int i = 0; i<4; i++){
		result[i] = res_l[i];
		result[i+4] = res_r[i];
	}
	return result;
}

vector<uint8_t> G_32(vector<uint8_t> block64, vector<uint8_t> key){
	vector<uint8_t> block_l(4);
	vector<uint8_t> block_r(4);	
	for(int i=0; i<4; i++){
		block_l[i] = block64[i];
		block_r[i] = block64[i+4];
	}
	vector<uint8_t> tmp(4);
	tmp = g(block_r,key);
	tmp = Add_mod_2(tmp,block_l);
	vector<uint8_t> res_l(4);
	vector<uint8_t> res_r(4);	
	for(int i=0; i<4; i++){
		res_l[i] = tmp[i];
		res_r[i] = block_r[i];
	}
	vector<uint8_t> result(4*2);
	for(int i = 0; i<4; i++){
		result[i] = res_l[i];
		result[i+4] = res_r[i];
	}
	return result;
}

vector<uint8_t> encrypt(vector<uint8_t> block64, vector< vector<uint8_t> > it_key){
	vector<uint8_t> result(4*2);
	result = G(block64,it_key[0]);
	for(int i=1;i<31;i++){
		result = G(result,it_key[i]);
	}
	result = G_32(result,it_key[31]);
	return result;
}

vector<uint8_t> decrypt(vector<uint8_t> block64, vector< vector<uint8_t> > it_key){
	vector<uint8_t> result(4*2);
	result = G(block64,it_key[31]);
	for(int i=30;i>0;i--){
		result = G(result,it_key[i]);
	}
	result = G_32(result,it_key[0]);
	return result;
}

//ф-ции для режимов
uint64_t file_size(FILE *f){ 
   fseek(f, 0, SEEK_END);
   uint64_t size = ftell(f);
   fseek(f, 0, SEEK_SET);
   return size;
}

void pad_2(vector<uint8_t> & buf,uint64_t size){
	uint64_t extra = 8 - size % 8;
	buf[size] = 0x80;
	for(uint64_t i = size+1; i < size+extra;i++){
		buf[i] = 0x00;
	}
}

void ECB_encrypt(FILE* in, FILE* out, vector<uint8_t> key, uint64_t in_size){
	vector<uint8_t> buf(16);//8+8 байт на всякий случай
	vector<uint8_t> result(8);
	vector< vector<uint8_t> > it_key = Make_keys(key);	
	while(in_size){
		if(in_size > 8){
			read = fread(&buf[0],1,8,in);
			copy(buf.begin(),buf.begin()+8,result.begin());
			result = encrypt(result,it_key);
			fwrite(&result[0],1,8,out);
			in_size -=8;
		} else {
			read = fread(&buf[0],1,in_size,in);
			int quantity = in_size/8 +1;
			if(in_size == 0) {
				in_size = 8;
			}
			pad_2(buf,in_size);
			for(int i = 0; i<quantity; i++){
				copy(buf.begin()+i*8,buf.begin()+i*8+8,result.begin());
				result = encrypt(result,it_key);
				fwrite(&result[0],1,8,out);
			}
			in_size = 0;
		}
	}
}

void ECB_decrypt(FILE* in, FILE* out, vector<uint8_t> key, uint64_t in_size){
	vector<uint8_t> buf(8);
	vector< vector<uint8_t> > it_key = Make_keys(key);	
	while(in_size){
		if(in_size > 8){
			read = fread(&buf[0],1,8,in);
			buf = decrypt(buf,it_key);
			fwrite(&buf[0],1,8,out);
			in_size -=8;
		} else {
			read = fread(&buf[0],1,8,in);
			buf = decrypt(buf,it_key);

			int c = 7;//block_size - 1
			for (; c >= 0 && buf[c] == 0x00; c--);
			if (buf[c] == 0x80){
				fwrite(&buf[0],1,c,out);
			} else {
				//тут надо поругаться дали непаддированый текст
				throw(WRONG_INPUT);
			}
			in_size = 0;	
		}
	}

}

vector<uint8_t> Inc_ctr(vector<uint8_t> vec){
	vector<uint8_t> result(8);
	unsigned int sum = vec[7] + 1;
	vec[7] = sum & 0xff;
	for(int i=6; i>=0; i--){
		sum = (sum >> 8) + vec[i];
		vec[i] = sum & 0xff;
	}
	return vec;	
}

vector<uint8_t> Add_mod_2_64(vector<uint8_t> first,vector<uint8_t> second){
	vector<uint8_t> result(8);
	for (int i=0; i<8; i++){
		result[i] = first[i]^second[i];
	}
	return result;
}

void CTR_encrypt(FILE* in, FILE* out,FILE* iv, vector<uint8_t> key, uint64_t in_size){//iv 32 бита
	vector<uint8_t> ctr;
	uint8_t tmp;
	while((read = fread(&tmp,1,1,iv))){
		ctr.push_back(tmp);
	}
	if(ctr.size()!=4){
		//не 32 бита ругаемся
		throw(WRONG_IV);
	}
	for(int i = 0; i<4; i++){
		ctr.push_back(0x00);
	}
	vector< vector<uint8_t> > it_key = Make_keys(key);
	vector<uint8_t> buf(8);
	vector<uint8_t> result(8);
	while(in_size){
		result = encrypt(ctr,it_key);
		memset(&buf[0],0,8);
		read = fread(&buf[0],1,8,in);
		if(in_size >= 8){
			result = Add_mod_2_64(result,buf);
			fwrite(&result[0],1,8,out);
			in_size -= 8;
		} else {
			result = Add_mod_2_64(result, buf);
			fwrite(&result[0],1,in_size,out);			
			in_size = 0;
		}
		ctr = Inc_ctr(ctr);
	}
}

void CTR_decrypt(FILE* in, FILE* out,FILE* iv, vector<uint8_t> key, uint64_t in_size){
	CTR_encrypt(in,out,iv,key,in_size);
}

void OFB_encrypt(FILE* in, FILE* out,FILE* iv, vector<uint8_t> key, uint64_t in_size){
	vector<uint8_t> R;
	uint8_t tmp;
	while((read = fread(&tmp,1,1,iv))){
		R.push_back(tmp);
	}
	if(R.size()%8 != 0){
		//не кратно 64 ругаемся
		throw(WRONG_IV);
	}
	vector< vector<uint8_t> > it_key = Make_keys(key);
	vector<uint8_t> buf(8);
	vector<uint8_t> reg(8);
	while(in_size){
		copy(R.begin(),R.begin()+8, reg.begin());
		reg = encrypt(reg,it_key);
		R.reserve(R.size()+reg.size());
		R.insert(R.end(),reg.begin(),reg.end());
		R.erase(R.begin(),R.begin()+8);
		memset(&buf[0],0,8);
		read = fread(&buf[0],1,8,in);
		if(in_size >= 8){
			buf = Add_mod_2_64(reg,buf);
			fwrite(&buf[0],1,8,out);
			in_size -= 8;
		} else {
			buf = Add_mod_2_64(reg,buf);
			fwrite(&buf[0],1,in_size,out);
			in_size = 0;
		}
	}
}

void OFB_decrypt(FILE* in, FILE* out,FILE* iv, vector<uint8_t> key, uint64_t in_size){
	OFB_encrypt(in,out,iv,key,in_size);
}

void CBC_encrypt(FILE* in, FILE* out,FILE* iv, vector<uint8_t> key, uint64_t in_size){
	vector<uint8_t> R;
	uint8_t tmp;
	while((read = fread(&tmp,1,1,iv))){
		R.push_back(tmp);
	}
	if(R.size()%8 != 0){
		//не кратно 64 ругаемся
		throw(WRONG_IV);
	}
	vector< vector<uint8_t> > it_key = Make_keys(key);
	vector<uint8_t> buf(16);//8+8
	vector<uint8_t> result(8);
	vector<uint8_t> reg(8);
	if(in_size == 0) {
		vector<uint8_t> buf1(8);
		pad_2(buf1,0);
		int quantity = in_size/8 + 1;
		for(int i=0; i<quantity; i++){
				copy(buf.begin()+i*8,buf.begin()+i*8+8,result.begin());
				reg = Add_mod_2_64(reg,result);
				reg = encrypt(reg,it_key);
				R.reserve(R.size()+reg.size());
				R.insert(R.end(),reg.begin(),reg.end());
				R.erase(R.begin(),R.begin()+8);
				fwrite(&reg[0],1,8,out);
			}
		
	}	
	while(in_size){
		copy(R.begin(),R.begin()+8, reg.begin());
		if(in_size > 8){
			read = fread(&buf[0],1,8,in);
			copy(buf.begin(), buf.begin()+8,result.begin());
			reg = Add_mod_2_64(reg,result);
			reg = encrypt(reg,it_key);
			R.reserve(R.size()+reg.size());
			R.insert(R.end(),reg.begin(),reg.end());
			R.erase(R.begin(),R.begin()+8);
			fwrite(&reg[0],1,8,out);
			in_size -=8;
		} else {
			read = fread(&buf[0],1,in_size,in);
			int quantity = in_size/8 + 1;
			pad_2(buf,in_size);
			for(int i=0; i<quantity; i++){
				copy(buf.begin()+i*8,buf.begin()+i*8+8,result.begin());
				reg = Add_mod_2_64(reg,result);
				reg = encrypt(reg,it_key);
				R.reserve(R.size()+reg.size());
				R.insert(R.end(),reg.begin(),reg.end());
				R.erase(R.begin(),R.begin()+8);
				fwrite(&reg[0],1,8,out);
			}
			in_size = 0;
		}
	}
}

void CBC_decrypt(FILE* in, FILE* out,FILE* iv, vector<uint8_t> key, uint64_t in_size){
	vector<uint8_t> R;
	uint8_t tmp;
	while((read = fread(&tmp,1,1,iv))){
		R.push_back(tmp);
	}
	if(R.size()%8 != 0){
		//не кратно 64 ругаемся
		throw(WRONG_IV);
	}
	vector< vector<uint8_t> > it_key = Make_keys(key);
	vector<uint8_t> buf(8);
	vector<uint8_t> reg(8);
	while(in_size){
		copy(R.begin(),R.begin()+8, reg.begin());
		if(in_size > 8){
			read = fread(&buf[0],1,8,in);
			R.reserve(R.size()+buf.size());
			R.insert(R.end(),buf.begin(),buf.end());
			R.erase(R.begin(),R.begin()+8);
			buf = decrypt(buf,it_key);
			reg = Add_mod_2_64(reg,buf);
			fwrite(&reg[0],1,8,out);
			in_size -=8;
		} else {
			read = fread(&buf[0],1,8,in);
			buf = decrypt(buf,it_key);
			reg = Add_mod_2_64(reg,buf);
			int c = 7;//block_size - 1
			for (; c >= 0 && reg[c] == 0x00; c--);
			if (reg[c] == 0x80){
				fwrite(&reg[0],1,c,out);
			} else {
				//тут надо поругаться дали непаддированый текст

				//throw(WRONG_INPUT);
			}
			in_size = 0;
		}
	}
}

void CFB_encrypt(FILE* in, FILE* out,FILE* iv, vector<uint8_t> key, uint64_t in_size){
	vector<uint8_t> R;
	uint8_t tmp;
	while((read = fread(&tmp,1,1,iv))){
		R.push_back(tmp);
	}
	if(R.size()%8 != 0){
		//не кратно 64 ругаемся
		throw(WRONG_IV);
	}
	vector< vector<uint8_t> > it_key = Make_keys(key);
	vector<uint8_t> buf(16);//8+8
	vector<uint8_t> result(8);
	vector<uint8_t> reg(8);
	while(in_size){
		copy(R.begin(),R.begin()+8, reg.begin());
		if(in_size > 8){
			read = fread(&buf[0],1,8,in);
			copy(buf.begin(), buf.begin()+8,result.begin());
			reg = encrypt(reg,it_key);
			reg = Add_mod_2_64(reg,result);

			R.reserve(R.size()+reg.size());
			R.insert(R.end(),reg.begin(),reg.end());
			R.erase(R.begin(),R.begin()+8);

			fwrite(&reg[0],1,8,out);
			in_size -=8;
		} else {
			read = fread(&buf[0],1,in_size,in);
			int quantity = in_size/8 + 1;
			if(in_size == 0) {
				in_size = 8;
			}
			pad_2(buf,in_size);
			for(int i=0; i<quantity; i++){
				copy(buf.begin()+i*8,buf.begin()+i*8+8,result.begin());
				reg = encrypt(reg,it_key);
				reg = Add_mod_2_64(reg,result);	
				R.reserve(R.size()+reg.size());
				R.insert(R.end(),reg.begin(),reg.end());
				R.erase(R.begin(),R.begin()+8);
				fwrite(&reg[0],1,8,out);
			}
			in_size = 0;
		}
	}
}

void CFB_decrypt(FILE* in, FILE* out,FILE* iv, vector<uint8_t> key, uint64_t in_size){
	vector<uint8_t> R;
	uint8_t tmp;
	while((read = fread(&tmp,1,1,iv))){
		R.push_back(tmp);
	}
	if(R.size()%8 != 0){
		//не кратно 64 ругаемся
		throw(WRONG_IV);
	}
	vector< vector<uint8_t> > it_key = Make_keys(key);
	vector<uint8_t> buf(8);
	vector<uint8_t> reg(8);
	while(in_size){
		copy(R.begin(),R.begin()+8, reg.begin());
		if(in_size > 8){
			read = fread(&buf[0],1,8,in);
			reg = encrypt(reg,it_key);
			reg = Add_mod_2_64(reg,buf);
			R.reserve(R.size()+buf.size());
			R.insert(R.end(),buf.begin(),buf.end());
			R.erase(R.begin(),R.begin()+8);
			fwrite(&reg[0],1,8,out);
			in_size -=8;
		} else {
			read = fread(&buf[0],1,8,in);
			reg = encrypt(reg,it_key);
			reg = Add_mod_2_64(reg,buf);
			int c = 7;//block_size - 1
			for (; c >= 0 && reg[c] == 0x00; c--);
			if (reg[c] == 0x80){
				fwrite(&reg[0],1,c,out);
			} else {
				//тут надо поругаться дали непаддированый текст
				throw(WRONG_INPUT);
			}
			in_size = 0;
		}
	}
}

void pad_3(vector<uint8_t> & buf,uint64_t size){
	uint64_t extra = (8 - size % 8) % 8;
	if(extra){
		buf[size] = 0x80;
		for(uint64_t i = size+1; i < size+extra;i++){
			buf[i] = 0x00;
		}
	}
}

vector<uint8_t> Shift_left(vector<uint8_t> block,unsigned int val){
	uint64_t tmp = 0;
	vector<uint8_t> result(8);
	for(int i=0; i<8; i++){
		tmp = (tmp << 8) + block[i];
	}
	tmp = tmp << val;
	for(int i=0; i<8;i++){
		result[i] = tmp >> (56 - i*8);
	}
	return result;
}

void MAC(FILE* in,FILE* out, vector<uint8_t> key, uint64_t in_size){
	vector<uint8_t> C;
	for(int i = 0; i < 8; i++){
		C.push_back(0x00);
	}
	vector< vector<uint8_t> > it_key = Make_keys(key);
	vector<uint8_t> buf(8);
	while(in_size>8){
		read = fread(&buf[0],1,8,in);
		C = Add_mod_2_64(buf,C);
		C = encrypt(C,it_key);
		in_size -=8;
	}
	//обработка последнего блока
	read = fread(&buf[0],1,in_size,in);
	pad_3(buf,in_size);
	C = Add_mod_2_64(buf,C);

	//выработка доп ключей
	vector<uint8_t> K;
	for(int i = 0; i < 8; i++){
		K.push_back(0x00);
	}
	K = encrypt(K,it_key);

	vector<uint8_t> B(8);
	copy(K.begin(),K.begin()+7, B.begin());
	B[7] = 0x1b;

	if(!(K[0] & 0x80)){
		K = Shift_left(K,1);
	} else {
		K = Shift_left(K,1);
		K = Add_mod_2_64(K,B);
	}

	if(in_size < 8){
		if(!(K[0] & 0x80)){
		K = Shift_left(K,1);
		} else {
			K = Shift_left(K,1);
			K = Add_mod_2_64(K,B);
		}
	}

	C = Add_mod_2_64(C,K);
	C = encrypt(C,it_key);

	// s = 32 в примерах
	fwrite(&C[0],1,4,out);
}

set <string> methods = {"--ecb","--ctr","--ofb","--cbc","--cfb","--mac"};
set <string> modes = {"-e", "-d"};
set <string> key = {"-k"};
set <string> options = {"-i", "-o", "-v"};
set <string> help = {"-h", "--help"};

void HELP(int i){
	stringstream out;
	out<<"magma [-h|--help]"<<endl<<"magma [--ecb|--ctr|--ofb|--cbc|--cfb] {-e|-d} -k <key file> [options]"<<endl<<"magma --mac -k <key file> [options]"<<endl;
	out<<"• -h | --help - вывести описание флагов в stdout"<<endl;
	out<<"• режимы работы, по умолчанию используется режим ECB:"<<endl;
	out<<"    --ecb – ГОСТ Р 34.13-2015, пункт 5.1"<<endl;
	out<<"    --ctr – ГОСТ Р 34.13-2015, пункт 5.2"<<endl;
	out<<"    --ofb – ГОСТ Р 34.13-2015, пункт 5.3"<<endl;
	out<<"    --cbc – ГОСТ Р 34.13-2015, пункт 5.4"<<endl;
	out<<"    --cfb – ГОСТ Р 34.13-2015, пункт 5.5"<<endl;
	out<<"    --mac – ГОСТ Р 34.13-2015, пункт 5.6"<<endl;
	out<<"• -e – произвести зашифрование"<<endl;
	out<<"• -d – произвести расшифрование"<<endl;
	out<<"• -k <key file> – файл с бинарным ключом"<<endl;
	out<<"• [options]:"<<endl;
	out<<"    -i <input file> – входной файл, по умолчанию stdin;"<<endl;
	out<<"    -o <output file> – выходной файл, по умолчанию stdout;"<<endl;
	out<<"    -v <iv file> – файл с бинарным значением IV, по умолчанию IV=0 минимально допустимой длины;"<<endl;
	out<<"• [описание дополнительно реализованных флагов]"<<endl;
	if(!i){
		cout<<out.str();
	} else {
		cerr<<out.str();
	}
}

void Make_state(int argc, char** argv, map <string,string> &state){
	string tmp,tmp_,tmp__;
	for(int i=1; i<argc; i++){
		tmp = string(argv[i]);
		if(methods.find(tmp)!=methods.end()){
			if(state["method"] == ""){
				state["method"] = tmp;
			} else {
				throw(WRONG_FLAGS);
			}
		} else if(modes.find(tmp)!=modes.end()){
			if(state["mode"] == ""){
				state["mode"] = tmp;
			} else {
				throw(WRONG_FLAGS);
			}
		} else if(key.find(tmp)!=key.end()){
			if(state["key_file"] == ""){
				if(i+1<argc){
					tmp_ = string(argv[i+1]);
					if(methods.find(tmp_)==methods.end() &&
					   modes.find(tmp_)==modes.end() &&
					   key.find(tmp_)==key.end() &&
					   options.find(tmp_)==options.end() &&
					   help.find(tmp_)==help.end()){
						state["key_file"] = tmp_;
						i++;
					} else {
						throw(NO_KEY_FILE);
					}
				} else {
					throw(NO_KEY_FILE);
				}
			} else {
				throw(WRONG_FLAGS);
			}
		} else if(options.find(tmp)!=options.end()){
			if(tmp == "-i"){tmp_ = "input_file";}
			if(tmp == "-o"){tmp_ = "output_file";}
			if(tmp == "-v"){tmp_ = "iv_file";}
			if(state[tmp_] == ""){
				if(i+1<argc){
					tmp__= string(argv[i+1]);
					if(methods.find(tmp__)==methods.end() &&
					   modes.find(tmp__)==modes.end() &&
					   key.find(tmp__)==key.end() &&
					   options.find(tmp__)==options.end() &&
					   help.find(tmp__)==help.end()){
						state[tmp_] = tmp__;
						i++;
					} else {
						throw(NO_OPTION_FILE);
					}
				} else {
					throw(NO_OPTION_FILE);
				}
			} else {
				throw(WRONG_FLAGS);
			}
		} else if(help.find(tmp)!=help.end()){
			if(argc == 2){
				HELP(0);
			} else{
				throw(WRONG_FLAGS);
			}
		} else {
			throw(WRONG_FLAGS);
		}
	}
	if(state["key_file"] == ""){
		throw(NO_KEY_FILE);
	}
	if(state["method"] != "--mac" && state["mode"] == ""){
		throw(WRONG_FLAGS);
	}
	if(state["method"] == "--mac" && state["mode"] != ""){
		throw(WRONG_FLAGS);
	}	
}

void Parse_key(vector<uint8_t> &key,FILE *key_file){
	uint8_t tmp;
	while((read = fread(&tmp,1,1,key_file))){
		key.push_back(tmp);
	}
	if(key.size() != 32){
		throw(INVALID_KEY);
	}	
}

void ecb_handler(map <string,string> state, FILE* in, FILE* out, vector<uint8_t> key, uint64_t in_size){
	if(state["iv_file"] != ""){
		throw(IV_FILE_IS_NOT_NEEDED);
	} else if(state["mode"] == "-e"){
		ECB_encrypt(in,out,key,in_size);
	} else if(state["mode"] == "-d"){
		ECB_decrypt(in,out,key,in_size);
	}
}

void ctr_handler(map <string,string> state, FILE* in, FILE* out, vector<uint8_t> key, uint64_t in_size){
	FILE* iv_file;
	if(state["iv_file"] != ""){
		iv_file = fopen((state["iv_file"]).c_str(), "rb");
		uint64_t size = file_size(iv_file);
		if(size == 0){
			throw(EMPTY_IV);
		}
	} else {
		iv_file = tmpfile();
		vector<uint8_t> buf;
		for(int i = 0; i < 4; i++){
			buf.push_back(0x00);
		}
		fwrite(&buf[0],1,4,iv_file);
		fseek(iv_file, 0, SEEK_SET);
	}
	if(state["mode"] == "-e"){
		CTR_encrypt(in,out,iv_file,key,in_size);
	} else if(state["mode"] == "-d"){
		CTR_decrypt(in,out,iv_file,key,in_size);
	}
	fclose(iv_file);
}

void ofb_handler(map <string,string> state, FILE* in, FILE* out, vector<uint8_t> key, uint64_t in_size){
	FILE* iv_file;
	if(state["iv_file"] != ""){
		iv_file = fopen((state["iv_file"]).c_str(), "rb");
		uint64_t size = file_size(iv_file);
		if(size == 0){
			throw(EMPTY_IV);
		}
	} else {
		iv_file = tmpfile();
		vector<uint8_t> buf;
		for(int i = 0; i < 8; i++){
			buf.push_back(0x00);
		}
		fwrite(&buf[0],1,8,iv_file);
		fseek(iv_file, 0, SEEK_SET);
	}
	if(state["mode"] == "-e"){
		OFB_encrypt(in,out,iv_file,key,in_size);
	} else if(state["mode"] == "-d"){
		OFB_decrypt(in,out,iv_file,key,in_size);
	}
	fclose(iv_file);
}

void cbc_handler(map <string,string> state, FILE* in, FILE* out, vector<uint8_t> key, uint64_t in_size){
	FILE* iv_file;
	if(state["iv_file"] != ""){
		iv_file = fopen((state["iv_file"]).c_str(), "rb");
		uint64_t size = file_size(iv_file);
		if(size == 0){
			throw(EMPTY_IV);
		}
	} else {
		iv_file = tmpfile();
		vector<uint8_t> buf;
		for(int i = 0; i < 8; i++){
			buf.push_back(0x00);
		}
		fwrite(&buf[0],1,8,iv_file);
		fseek(iv_file, 0, SEEK_SET);
	}
	if(state["mode"] == "-e"){
		CBC_encrypt(in,out,iv_file,key,in_size);
	} else if(state["mode"] == "-d"){
		CBC_decrypt(in,out,iv_file,key,in_size);
	}
	fclose(iv_file);
}

void cfb_handler(map <string,string> state, FILE* in, FILE* out, vector<uint8_t> key, uint64_t in_size){
	FILE* iv_file;
	if(state["iv_file"] != ""){
		iv_file = fopen((state["iv_file"]).c_str(), "rb");
		uint64_t size = file_size(iv_file);
		if(size == 0){
			throw(EMPTY_IV);
		}
	} else {
		iv_file = tmpfile();
		vector<uint8_t> buf;
		for(int i = 0; i < 8; i++){
			buf.push_back(0x00);
		}
		fwrite(&buf[0],1,8,iv_file);
		fseek(iv_file, 0, SEEK_SET);
	}
	if(state["mode"] == "-e"){
		CFB_encrypt(in,out,iv_file,key,in_size);
	} else if(state["mode"] == "-d"){
		CFB_decrypt(in,out,iv_file,key,in_size);
	}
	fclose(iv_file);
}

void mac_handler(map <string,string> state, FILE* in, FILE* out, vector<uint8_t> key, uint64_t in_size){
	MAC(in,out,key,in_size);
}

int main(int argc, char** argv){
	try{
		map <string,string> state = { {"method", ""},
									  {"mode", ""},
									  {"key_file", ""},
									  {"input_file", ""},
									  {"output_file", ""},
									  {"iv_file", ""},
									};
		Make_state(argc,argv,state);
		FILE *key_file = fopen((state["key_file"]).c_str(), "rb");
		if(key_file == NULL){
			throw(CANNOT_OPEN_KEY_FILE);
		}
		vector<uint8_t> key;
		Parse_key(key,key_file);

		FILE* input_file;
		if(state["input_file"] != ""){
			input_file = fopen((state["input_file"]).c_str(), "rb");
			if(input_file == NULL){
				throw(CANNOT_OPEN_INPUT_FILE);
			}
		} else {
			const char* filename = NULL;
			FILE * fin = freopen(filename, "rb", stdin);
			input_file = tmpfile();
			vector<uint8_t> buf(8);
			while((read = fread(&buf[0],1,8,fin))){
				fwrite(&buf[0],1,8,input_file);
			}
		}
		uint64_t in_size = file_size(input_file);
		if(in_size == 0){
			//throw(EMPTY_INPUT);
		}
		FILE *output_file;
		int stdout_flag = 0;
		if(state["output_file"] != ""){
			output_file = fopen((state["output_file"]).c_str(), "wb");
			if(output_file == NULL){
				throw(CANNOT_OPEN_OUTPUT_FILE);
			}
		} else {
			stdout_flag = 1;
			output_file = tmpfile();
		}
		if(state["method"] == "" || state["method"] == "--ecb"){ ecb_handler(state, input_file, output_file, key, in_size); }
		else if(state["method"] == "--ctr"){ ctr_handler(state, input_file, output_file, key, in_size); }
		else if(state["method"] == "--ofb"){ ofb_handler(state, input_file, output_file, key, in_size); }
		else if(state["method"] == "--cbc"){ cbc_handler(state, input_file, output_file, key, in_size); }
		else if(state["method"] == "--cfb"){ cfb_handler(state, input_file, output_file, key, in_size); }
		else if(state["method"] == "--mac"){ mac_handler(state, input_file, output_file, key, in_size); }
		if(stdout_flag == 1){
			fseek(output_file, 0, SEEK_SET);
			vector<uint8_t> buff(1);
			while((read = fread(&buff[0],1,1,output_file))){	
				for_each(buff.begin(),buff.end(),[] (uint8_t c) {std::cout<<setfill('0')<<setw(2)<<std::hex<<int(c);} );
			}
			cout<<endl;
		}
		fclose(key_file);
		fclose(input_file);
		fclose(output_file);
	} catch(ERRORS err){
		switch(err){
			case WRONG_FLAGS: cerr<<"WRONG_FLAGS"<<endl; HELP(1); break;
			case NO_KEY_FILE: cerr<<"NO_KEY_FILE"<<endl; HELP(1); break;
			case NO_OPTION_FILE: cerr<<"NO_OPTION_FILE"<<endl; HELP(1); break;
			case CANNOT_OPEN_KEY_FILE: cerr<<"CANNOT_OPEN_KEY_FILE"<<endl;  HELP(1); break;
			case INVALID_KEY: cerr<<"INVALID_KEY"<<endl;  HELP(1);break;
			case CANNOT_OPEN_INPUT_FILE: cerr<<"CANNOT_OPEN_INPUT_FILE"<<endl;  HELP(1);break;
			case CANNOT_OPEN_OUTPUT_FILE: cerr<<"CANNOT_OPEN_OUTPUT_FILE"<<endl; HELP(1); break;
			case EMPTY_INPUT: cerr<<"EMPTY_INPUT"<<endl;  HELP(1); break;
			case IV_FILE_IS_NOT_NEEDED:cerr<<"IV_FILE_IS_NOT_NEEDED"<<endl; HELP(1); break;
			case WRONG_INPUT: cerr<<"WRONG_INPUT"<<endl; HELP(1); break;
			case WRONG_IV: cerr<<"WRONG_IV"<<endl; HELP(1); break;
			case EMPTY_IV: cerr<<"EMPTY_IV"<<endl;  HELP(1); break;
			default:cerr<<"ERROR"<<endl;break;
		}
	}
}