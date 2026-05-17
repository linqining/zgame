let wasm_bindgen = (function(exports) {
    let script_src;
    if (typeof document !== 'undefined' && document.currentScript !== null) {
        script_src = new URL(document.currentScript.src, location.href).toString();
    }

    class WasmClientPlayer {
        static __wrap(ptr) {
            ptr = ptr >>> 0;
            const obj = Object.create(WasmClientPlayer.prototype);
            obj.__wbg_ptr = ptr;
            WasmClientPlayerFinalization.register(obj, obj.__wbg_ptr, obj);
            return obj;
        }
        __destroy_into_raw() {
            const ptr = this.__wbg_ptr;
            this.__wbg_ptr = 0;
            WasmClientPlayerFinalization.unregister(this);
            return ptr;
        }
        free() {
            const ptr = this.__destroy_into_raw();
            wasm.__wbg_wasmclientplayer_free(ptr, 0);
        }
        /**
         * @param {string} cts_json
         * @returns {any}
         */
        batch_generate_reveal_token(cts_json) {
            const ptr0 = passStringToWasm0(cts_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmclientplayer_batch_generate_reveal_token(this.__wbg_ptr, ptr0, len0);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return takeFromExternrefTable0(ret[0]);
        }
        /**
         * @param {string} ct_json
         * @returns {string}
         */
        decrypt_card(ct_json) {
            let deferred3_0;
            let deferred3_1;
            try {
                const ptr0 = passStringToWasm0(ct_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len0 = WASM_VECTOR_LEN;
                const ret = wasm.wasmclientplayer_decrypt_card(this.__wbg_ptr, ptr0, len0);
                var ptr2 = ret[0];
                var len2 = ret[1];
                if (ret[3]) {
                    ptr2 = 0; len2 = 0;
                    throw takeFromExternrefTable0(ret[2]);
                }
                deferred3_0 = ptr2;
                deferred3_1 = len2;
                return getStringFromWasm0(ptr2, len2);
            } finally {
                wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
            }
        }
        /**
         * @param {string} ct_json
         * @param {string} other_tokens_json
         * @returns {string}
         */
        decrypt_playing_card(ct_json, other_tokens_json) {
            let deferred4_0;
            let deferred4_1;
            try {
                const ptr0 = passStringToWasm0(ct_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len0 = WASM_VECTOR_LEN;
                const ptr1 = passStringToWasm0(other_tokens_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len1 = WASM_VECTOR_LEN;
                const ret = wasm.wasmclientplayer_decrypt_playing_card(this.__wbg_ptr, ptr0, len0, ptr1, len1);
                var ptr3 = ret[0];
                var len3 = ret[1];
                if (ret[3]) {
                    ptr3 = 0; len3 = 0;
                    throw takeFromExternrefTable0(ret[2]);
                }
                deferred4_0 = ptr3;
                deferred4_1 = len3;
                return getStringFromWasm0(ptr3, len3);
            } finally {
                wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
            }
        }
        /**
         * @param {string} ct_json
         * @param {string} tokens_hexes
         * @returns {string}
         */
        distributed_decrypt(ct_json, tokens_hexes) {
            let deferred4_0;
            let deferred4_1;
            try {
                const ptr0 = passStringToWasm0(ct_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len0 = WASM_VECTOR_LEN;
                const ptr1 = passStringToWasm0(tokens_hexes, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len1 = WASM_VECTOR_LEN;
                const ret = wasm.wasmclientplayer_distributed_decrypt(this.__wbg_ptr, ptr0, len0, ptr1, len1);
                var ptr3 = ret[0];
                var len3 = ret[1];
                if (ret[3]) {
                    ptr3 = 0; len3 = 0;
                    throw takeFromExternrefTable0(ret[2]);
                }
                deferred4_0 = ptr3;
                deferred4_1 = len3;
                return getStringFromWasm0(ptr3, len3);
            } finally {
                wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
            }
        }
        /**
         * @param {string} ct_json
         * @param {string} tokens_json
         * @returns {string}
         */
        distributed_decrypt_from_tokens(ct_json, tokens_json) {
            let deferred4_0;
            let deferred4_1;
            try {
                const ptr0 = passStringToWasm0(ct_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len0 = WASM_VECTOR_LEN;
                const ptr1 = passStringToWasm0(tokens_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len1 = WASM_VECTOR_LEN;
                const ret = wasm.wasmclientplayer_distributed_decrypt_from_tokens(this.__wbg_ptr, ptr0, len0, ptr1, len1);
                var ptr3 = ret[0];
                var len3 = ret[1];
                if (ret[3]) {
                    ptr3 = 0; len3 = 0;
                    throw takeFromExternrefTable0(ret[2]);
                }
                deferred4_0 = ptr3;
                deferred4_1 = len3;
                return getStringFromWasm0(ptr3, len3);
            } finally {
                wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
            }
        }
        /**
         * @param {string} sk_hex
         * @returns {WasmClientPlayer}
         */
        static from_sk(sk_hex) {
            const ptr0 = passStringToWasm0(sk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmclientplayer_from_sk(ptr0, len0);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return WasmClientPlayer.__wrap(ret[0]);
        }
        /**
         * @param {string} hand_encrypted_json
         * @param {string} deck_plaintext_json
         * @param {string} agg_pk_hex
         * @param {string} per_card_tokens_json
         * @returns {any}
         */
        generate_expel_proof(hand_encrypted_json, deck_plaintext_json, agg_pk_hex, per_card_tokens_json) {
            const ptr0 = passStringToWasm0(hand_encrypted_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(deck_plaintext_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(agg_pk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len2 = WASM_VECTOR_LEN;
            const ptr3 = passStringToWasm0(per_card_tokens_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len3 = WASM_VECTOR_LEN;
            const ret = wasm.wasmclientplayer_generate_expel_proof(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return takeFromExternrefTable0(ret[0]);
        }
        /**
         * @returns {any}
         */
        generate_pk_proof() {
            const ret = wasm.wasmclientplayer_generate_pk_proof(this.__wbg_ptr);
            return ret;
        }
        /**
         * @param {string} ct_json
         * @returns {any}
         */
        generate_reveal_token(ct_json) {
            const ptr0 = passStringToWasm0(ct_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmclientplayer_generate_reveal_token(this.__wbg_ptr, ptr0, len0);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return takeFromExternrefTable0(ret[0]);
        }
        /**
         * @returns {string}
         */
        get_pk_hex() {
            let deferred1_0;
            let deferred1_1;
            try {
                const ret = wasm.wasmclientplayer_get_pk_hex(this.__wbg_ptr);
                deferred1_0 = ret[0];
                deferred1_1 = ret[1];
                return getStringFromWasm0(ret[0], ret[1]);
            } finally {
                wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
            }
        }
        /**
         * @returns {string}
         */
        get_sk_hex() {
            let deferred1_0;
            let deferred1_1;
            try {
                const ret = wasm.wasmclientplayer_get_sk_hex(this.__wbg_ptr);
                deferred1_0 = ret[0];
                deferred1_1 = ret[1];
                return getStringFromWasm0(ret[0], ret[1]);
            } finally {
                wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
            }
        }
        /**
         * @param {string} deck_encrypted_json
         * @param {string} agg_pk_hex
         * @returns {any}
         */
        join_game_and_shuffle(deck_encrypted_json, agg_pk_hex) {
            const ptr0 = passStringToWasm0(deck_encrypted_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(agg_pk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.wasmclientplayer_join_game_and_shuffle(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return takeFromExternrefTable0(ret[0]);
        }
        /**
         * @param {string} plaintext_hex
         * @param {string} pk_hex
         * @returns {any}
         */
        mask_card(plaintext_hex, pk_hex) {
            const ptr0 = passStringToWasm0(plaintext_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(pk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.wasmclientplayer_mask_card(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return takeFromExternrefTable0(ret[0]);
        }
        constructor() {
            const ret = wasm.wasmclientplayer_new();
            this.__wbg_ptr = ret >>> 0;
            WasmClientPlayerFinalization.register(this, this.__wbg_ptr, this);
            return this;
        }
        /**
         * @param {string} ct_json
         * @param {string} tokens_json
         * @returns {string}
         */
        peek_card(ct_json, tokens_json) {
            let deferred4_0;
            let deferred4_1;
            try {
                const ptr0 = passStringToWasm0(ct_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len0 = WASM_VECTOR_LEN;
                const ptr1 = passStringToWasm0(tokens_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len1 = WASM_VECTOR_LEN;
                const ret = wasm.wasmclientplayer_peek_card(this.__wbg_ptr, ptr0, len0, ptr1, len1);
                var ptr3 = ret[0];
                var len3 = ret[1];
                if (ret[3]) {
                    ptr3 = 0; len3 = 0;
                    throw takeFromExternrefTable0(ret[2]);
                }
                deferred4_0 = ptr3;
                deferred4_1 = len3;
                return getStringFromWasm0(ptr3, len3);
            } finally {
                wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
            }
        }
        /**
         * @param {string} ct_json
         * @returns {string}
         */
        peek_own_card(ct_json) {
            let deferred3_0;
            let deferred3_1;
            try {
                const ptr0 = passStringToWasm0(ct_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len0 = WASM_VECTOR_LEN;
                const ret = wasm.wasmclientplayer_peek_own_card(this.__wbg_ptr, ptr0, len0);
                var ptr2 = ret[0];
                var len2 = ret[1];
                if (ret[3]) {
                    ptr2 = 0; len2 = 0;
                    throw takeFromExternrefTable0(ret[2]);
                }
                deferred3_0 = ptr2;
                deferred3_1 = len2;
                return getStringFromWasm0(ptr2, len2);
            } finally {
                wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
            }
        }
        /**
         * @param {string} ct_json
         * @param {string} pk_hex
         * @returns {any}
         */
        remask_card(ct_json, pk_hex) {
            const ptr0 = passStringToWasm0(ct_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(pk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.wasmclientplayer_remask_card(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return takeFromExternrefTable0(ret[0]);
        }
        /**
         * @param {string} comm_plaintext_hex
         * @returns {any}
         */
        reveal_community(comm_plaintext_hex) {
            const ptr0 = passStringToWasm0(comm_plaintext_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmclientplayer_reveal_community(this.__wbg_ptr, ptr0, len0);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return takeFromExternrefTable0(ret[0]);
        }
        /**
         * @param {number} hand_index
         * @param {string} hand_encrypted_json
         * @param {string} deck_plaintext_json
         * @param {string} agg_pk_hex
         * @returns {any}
         */
        reveal_own_card(hand_index, hand_encrypted_json, deck_plaintext_json, agg_pk_hex) {
            const ptr0 = passStringToWasm0(hand_encrypted_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(deck_plaintext_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(agg_pk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len2 = WASM_VECTOR_LEN;
            const ret = wasm.wasmclientplayer_reveal_own_card(this.__wbg_ptr, hand_index, ptr0, len0, ptr1, len1, ptr2, len2);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return takeFromExternrefTable0(ret[0]);
        }
        /**
         * @param {string} deck_encrypted_json
         * @param {string} agg_pk_hex
         * @returns {any}
         */
        shuffle(deck_encrypted_json, agg_pk_hex) {
            const ptr0 = passStringToWasm0(deck_encrypted_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(agg_pk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.wasmclientplayer_shuffle(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return takeFromExternrefTable0(ret[0]);
        }
        /**
         * @returns {any}
         */
        to_keys() {
            const ret = wasm.wasmclientplayer_to_keys(this.__wbg_ptr);
            return ret;
        }
        /**
         * @param {string} token_json
         * @returns {string}
         */
        static verify_and_reveal_from_token(token_json) {
            let deferred3_0;
            let deferred3_1;
            try {
                const ptr0 = passStringToWasm0(token_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                const len0 = WASM_VECTOR_LEN;
                const ret = wasm.wasmclientplayer_verify_and_reveal_from_token(ptr0, len0);
                var ptr2 = ret[0];
                var len2 = ret[1];
                if (ret[3]) {
                    ptr2 = 0; len2 = 0;
                    throw takeFromExternrefTable0(ret[2]);
                }
                deferred3_0 = ptr2;
                deferred3_1 = len2;
                return getStringFromWasm0(ptr2, len2);
            } finally {
                wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
            }
        }
        /**
         * @param {string} input_cards_json
         * @param {string} mask_cards_json
         * @param {string} remask_proof_json
         * @param {string} pk_hex
         * @returns {any}
         */
        verify_remask_proof(input_cards_json, mask_cards_json, remask_proof_json, pk_hex) {
            const ptr0 = passStringToWasm0(input_cards_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(mask_cards_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(remask_proof_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len2 = WASM_VECTOR_LEN;
            const ptr3 = passStringToWasm0(pk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len3 = WASM_VECTOR_LEN;
            const ret = wasm.wasmclientplayer_verify_remask_proof(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return takeFromExternrefTable0(ret[0]);
        }
    }
    if (Symbol.dispose) WasmClientPlayer.prototype[Symbol.dispose] = WasmClientPlayer.prototype.free;
    exports.WasmClientPlayer = WasmClientPlayer;

    /**
     * @param {string} pk_hexes
     * @returns {string}
     */
    function compute_aggregate_key(pk_hexes) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(pk_hexes, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.compute_aggregate_key(ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    exports.compute_aggregate_key = compute_aggregate_key;

    /**
     * @param {string} plaintext_hex
     * @param {string} pk_hex
     * @returns {any}
     */
    function encrypt_plaintext(plaintext_hex, pk_hex) {
        const ptr0 = passStringToWasm0(plaintext_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(pk_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.encrypt_plaintext(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    exports.encrypt_plaintext = encrypt_plaintext;
    function __wbg_get_imports() {
        const import0 = {
            __proto__: null,
            __wbg___wbindgen_is_function_3baa9db1a987f47d: function(arg0) {
                const ret = typeof(arg0) === 'function';
                return ret;
            },
            __wbg___wbindgen_is_object_63322ec0cd6ea4ef: function(arg0) {
                const val = arg0;
                const ret = typeof(val) === 'object' && val !== null;
                return ret;
            },
            __wbg___wbindgen_is_string_6df3bf7ef1164ed3: function(arg0) {
                const ret = typeof(arg0) === 'string';
                return ret;
            },
            __wbg___wbindgen_is_undefined_29a43b4d42920abd: function(arg0) {
                const ret = arg0 === undefined;
                return ret;
            },
            __wbg___wbindgen_throw_6b64449b9b9ed33c: function(arg0, arg1) {
                throw new Error(getStringFromWasm0(arg0, arg1));
            },
            __wbg_call_a24592a6f349a97e: function() { return handleError(function (arg0, arg1, arg2) {
                const ret = arg0.call(arg1, arg2);
                return ret;
            }, arguments); },
            __wbg_crypto_38df2bab126b63dc: function(arg0) {
                const ret = arg0.crypto;
                return ret;
            },
            __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
                arg0.getRandomValues(arg1);
            }, arguments); },
            __wbg_length_9f1775224cf1d815: function(arg0) {
                const ret = arg0.length;
                return ret;
            },
            __wbg_log_cde4f3b93782a5f4: function(arg0, arg1) {
                console.log(getStringFromWasm0(arg0, arg1));
            },
            __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
                const ret = arg0.msCrypto;
                return ret;
            },
            __wbg_new_c4243e04577aa187: function() {
                const ret = new Object();
                return ret;
            },
            __wbg_new_with_length_8c854e41ea4dae9b: function(arg0) {
                const ret = new Uint8Array(arg0 >>> 0);
                return ret;
            },
            __wbg_node_84ea875411254db1: function(arg0) {
                const ret = arg0.node;
                return ret;
            },
            __wbg_process_44c7a14e11e9f69e: function(arg0) {
                const ret = arg0.process;
                return ret;
            },
            __wbg_prototypesetcall_a6b02eb00b0f4ce2: function(arg0, arg1, arg2) {
                Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
            },
            __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
                arg0.randomFillSync(arg1);
            }, arguments); },
            __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
                const ret = module.require;
                return ret;
            }, arguments); },
            __wbg_set_d704175508dec5f7: function(arg0, arg1, arg2) {
                arg0[arg1] = arg2;
            },
            __wbg_static_accessor_GLOBAL_8cfadc87a297ca02: function() {
                const ret = typeof global === 'undefined' ? null : global;
                return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
            },
            __wbg_static_accessor_GLOBAL_THIS_602256ae5c8f42cf: function() {
                const ret = typeof globalThis === 'undefined' ? null : globalThis;
                return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
            },
            __wbg_static_accessor_SELF_e445c1c7484aecc3: function() {
                const ret = typeof self === 'undefined' ? null : self;
                return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
            },
            __wbg_static_accessor_WINDOW_f20e8576ef1e0f17: function() {
                const ret = typeof window === 'undefined' ? null : window;
                return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
            },
            __wbg_subarray_f8ca46a25b1f5e0d: function(arg0, arg1, arg2) {
                const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
                return ret;
            },
            __wbg_versions_276b2795b1c6a219: function(arg0) {
                const ret = arg0.versions;
                return ret;
            },
            __wbindgen_cast_0000000000000001: function(arg0, arg1) {
                // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
                const ret = getArrayU8FromWasm0(arg0, arg1);
                return ret;
            },
            __wbindgen_cast_0000000000000002: function(arg0, arg1) {
                // Cast intrinsic for `Ref(String) -> Externref`.
                const ret = getStringFromWasm0(arg0, arg1);
                return ret;
            },
            __wbindgen_init_externref_table: function() {
                const table = wasm.__wbindgen_externrefs;
                const offset = table.grow(4);
                table.set(0, undefined);
                table.set(offset + 0, undefined);
                table.set(offset + 1, null);
                table.set(offset + 2, true);
                table.set(offset + 3, false);
            },
        };
        return {
            __proto__: null,
            "./client_wasm_bg.js": import0,
        };
    }

    const WasmClientPlayerFinalization = (typeof FinalizationRegistry === 'undefined')
        ? { register: () => {}, unregister: () => {} }
        : new FinalizationRegistry(ptr => wasm.__wbg_wasmclientplayer_free(ptr >>> 0, 1));

    function addToExternrefTable0(obj) {
        const idx = wasm.__externref_table_alloc();
        wasm.__wbindgen_externrefs.set(idx, obj);
        return idx;
    }

    function getArrayU8FromWasm0(ptr, len) {
        ptr = ptr >>> 0;
        return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
    }

    function getStringFromWasm0(ptr, len) {
        ptr = ptr >>> 0;
        return decodeText(ptr, len);
    }

    let cachedUint8ArrayMemory0 = null;
    function getUint8ArrayMemory0() {
        if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
            cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
        }
        return cachedUint8ArrayMemory0;
    }

    function handleError(f, args) {
        try {
            return f.apply(this, args);
        } catch (e) {
            const idx = addToExternrefTable0(e);
            wasm.__wbindgen_exn_store(idx);
        }
    }

    function isLikeNone(x) {
        return x === undefined || x === null;
    }

    function passStringToWasm0(arg, malloc, realloc) {
        if (realloc === undefined) {
            const buf = cachedTextEncoder.encode(arg);
            const ptr = malloc(buf.length, 1) >>> 0;
            getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
            WASM_VECTOR_LEN = buf.length;
            return ptr;
        }

        let len = arg.length;
        let ptr = malloc(len, 1) >>> 0;

        const mem = getUint8ArrayMemory0();

        let offset = 0;

        for (; offset < len; offset++) {
            const code = arg.charCodeAt(offset);
            if (code > 0x7F) break;
            mem[ptr + offset] = code;
        }
        if (offset !== len) {
            if (offset !== 0) {
                arg = arg.slice(offset);
            }
            ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
            const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
            const ret = cachedTextEncoder.encodeInto(arg, view);

            offset += ret.written;
            ptr = realloc(ptr, len, offset, 1) >>> 0;
        }

        WASM_VECTOR_LEN = offset;
        return ptr;
    }

    function takeFromExternrefTable0(idx) {
        const value = wasm.__wbindgen_externrefs.get(idx);
        wasm.__externref_table_dealloc(idx);
        return value;
    }

    let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
    cachedTextDecoder.decode();
    function decodeText(ptr, len) {
        return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
    }

    const cachedTextEncoder = new TextEncoder();

    if (!('encodeInto' in cachedTextEncoder)) {
        cachedTextEncoder.encodeInto = function (arg, view) {
            const buf = cachedTextEncoder.encode(arg);
            view.set(buf);
            return {
                read: arg.length,
                written: buf.length
            };
        };
    }

    let WASM_VECTOR_LEN = 0;

    let wasmModule, wasm;
    function __wbg_finalize_init(instance, module) {
        wasm = instance.exports;
        wasmModule = module;
        cachedUint8ArrayMemory0 = null;
        wasm.__wbindgen_start();
        return wasm;
    }

    async function __wbg_load(module, imports) {
        if (typeof Response === 'function' && module instanceof Response) {
            if (typeof WebAssembly.instantiateStreaming === 'function') {
                try {
                    return await WebAssembly.instantiateStreaming(module, imports);
                } catch (e) {
                    const validResponse = module.ok && expectedResponseType(module.type);

                    if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                        console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                    } else { throw e; }
                }
            }

            const bytes = await module.arrayBuffer();
            return await WebAssembly.instantiate(bytes, imports);
        } else {
            const instance = await WebAssembly.instantiate(module, imports);

            if (instance instanceof WebAssembly.Instance) {
                return { instance, module };
            } else {
                return instance;
            }
        }

        function expectedResponseType(type) {
            switch (type) {
                case 'basic': case 'cors': case 'default': return true;
            }
            return false;
        }
    }

    function initSync(module) {
        if (wasm !== undefined) return wasm;


        if (module !== undefined) {
            if (Object.getPrototypeOf(module) === Object.prototype) {
                ({module} = module)
            } else {
                console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
            }
        }

        const imports = __wbg_get_imports();
        if (!(module instanceof WebAssembly.Module)) {
            module = new WebAssembly.Module(module);
        }
        const instance = new WebAssembly.Instance(module, imports);
        return __wbg_finalize_init(instance, module);
    }

    async function __wbg_init(module_or_path) {
        if (wasm !== undefined) return wasm;


        if (module_or_path !== undefined) {
            if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
                ({module_or_path} = module_or_path)
            } else {
                console.warn('using deprecated parameters for the initialization function; pass a single object instead')
            }
        }

        if (module_or_path === undefined && script_src !== undefined) {
            module_or_path = script_src.replace(/\.js$/, "_bg.wasm");
        }
        const imports = __wbg_get_imports();

        if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
            module_or_path = fetch(module_or_path);
        }

        const { instance, module } = await __wbg_load(await module_or_path, imports);

        return __wbg_finalize_init(instance, module);
    }

    return Object.assign(__wbg_init, { initSync }, exports);
})({ __proto__: null });
