#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <nan.h>
#include <cstddef>
#include <cassert>
#include <cstring>

#include "KeccakNISTInterface.h"

#define MAX_DIGEST_SIZE 64
#define ASSERT_IS_STRING_OR_BUFFER(val) \
	if (!val->IsString() && !Buffer::HasInstance(val)) { \
		return NanThrowError(Exception::TypeError(NanNew<String>("Not a string or buffer"))); \
	}

using namespace node;
using namespace v8;
using namespace Node_SHA3;

static void toHex(const char *data_buf, size_t size, char *output);

class SHA3Hash: public ObjectWrap {
public:
	hashState state;
	int32_t bitlen;

	static void
	Initialize(Handle<Object> target) {
		NanScope();
		Local<FunctionTemplate> t = NanNew<FunctionTemplate>(New);
		t->InstanceTemplate()->SetInternalFieldCount(1);
		t->SetClassName(NanNew<String>("SHA3Hash"));

		NODE_SET_PROTOTYPE_METHOD(t, "update", Update);
		NODE_SET_PROTOTYPE_METHOD(t, "digest", Digest);

		NanAssignPersistent(constructor, t->GetFunction());
		target->Set(NanNew<String>("SHA3Hash"), t->GetFunction());
	}

	static
	NAN_METHOD(New) {
		NanScope();
		SHA3Hash *obj;
		int32_t hashlen;

		hashlen = args[0]->IsUndefined() ? 512 : args[0]->Int32Value();
		switch (hashlen) {
			case 224:
			case 256:
			case 384:
			case 512:
				break;
			default:
				Local<Value> exception = Exception::TypeError(NanNew<String>("Unsupported hash length"));
				return NanThrowError(exception);
		}

		if (args.IsConstructCall()) {
			// Invoked as constructor.
			obj = new SHA3Hash();
			obj->Wrap(args.This());
			obj->bitlen = hashlen;
			::Init(&obj->state, hashlen);
			NanReturnValue(args.This());
		} else {
			// Invoked as a plain function.
			const int argc = 1;
			Local<Value> argv[argc] = { NanNew<Number>(hashlen) };
			Local<Function> cons = NanNew<Function>(constructor);
			NanReturnValue(cons->NewInstance(argc, argv));
		}
	}

	static
	NAN_METHOD(Update) {
		NanScope();
		SHA3Hash *obj = ObjectWrap::Unwrap<SHA3Hash>(args.This());

		ASSERT_IS_STRING_OR_BUFFER(args[0]);
		enum encoding enc = ParseEncoding(args[1]);
		ssize_t len = DecodeBytes(args[0], enc);

		if (len < 0) {
			Local<Value> exception = Exception::Error(NanNew<String>("Bad argument"));
			return NanThrowError(exception);
		}

		if (Buffer::HasInstance(args[0])) {
			Local<Object> buffer_obj = args[0]->ToObject();
			const char *buffer_data = Buffer::Data(buffer_obj);
			size_t buffer_length = Buffer::Length(buffer_obj);
			::Update(&obj->state, (const BitSequence *) buffer_data, buffer_length * 8);
		} else {
			char *buf = new char[len];
			ssize_t written = DecodeWrite(buf, len, args[0], enc);
			assert(written == len);
			::Update(&obj->state, (const BitSequence *) buf, len * 8);
			delete[] buf;
		}

		NanReturnValue(args.This());
	}

	static
	NAN_METHOD(Digest) {
		NanScope();
		SHA3Hash *obj = ObjectWrap::Unwrap<SHA3Hash>(args.This());
		hashState state2;
		unsigned char digest[MAX_DIGEST_SIZE];

		memcpy(&state2, &obj->state, sizeof(hashState));
		Final(&state2, digest);

		Local<Value> outString;
		enum encoding enc = ParseEncoding(args[0], BINARY);
		if (enc == HEX) {
			// Hex encoding
			char hexdigest[MAX_DIGEST_SIZE * 2];
			toHex((const char *) digest, obj->bitlen / 8, hexdigest);
			outString = Encode(hexdigest, obj->bitlen / 4, BINARY);
		} else if (enc == BINARY /* || enc == BUFFER */) {
			outString = Encode(digest, obj->bitlen / 8, enc);
		} else {
			Local<Value> exception = Exception::Error(NanNew<String>("Unsupported output encoding"));
			return NanThrowError(exception);
		}

		NanReturnValue(outString);
	}

private:
	static Persistent<Function> constructor;
};

Persistent<Function> SHA3Hash::constructor;

static const char hex_chars[] = {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
	'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
	'u', 'v', 'w', 'x', 'y', 'z'
};

static void
toHex(const char *data_buf, size_t size, char *output) {
	size_t i;

	for (i = 0; i < size; i++) {
		output[i * 2] = hex_chars[(unsigned char) data_buf[i] / 16];
		output[i * 2 + 1] = hex_chars[(unsigned char) data_buf[i] % 16];
	}
}

static void
init(Handle<Object> target) {
	SHA3Hash::Initialize(target);
}

NODE_MODULE(sha3, init)
