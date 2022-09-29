/*
 * Copyright 2022 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

//==========================================================
// Includes.
//

#include <encode.h>

#include <utils.h>


//==========================================================
// Public API.
//

/*
 * Deallocates the fields of a udf_param UDF file record.
 *
 * @param param  The udf_param to be deallocated.
 */
void
free_udf(udf_param *param)
{
	cf_free(param->name);
	cf_free(param->data);
}

/*
 * Deallocates a vector of udf_param UDF file records.
 *
 * @param udf_vec  The vector of udf_param records to be deallocated.
 */
void
free_udfs(as_vector *udf_vec)
{
	ver("Freeing %u UDF file(s)", udf_vec->size);

	for (uint32_t i = 0; i < udf_vec->size; ++i) {
		udf_param *param = as_vector_get(udf_vec, i);
		free_udf(param);
	}
}

/*
 * Deallocates the fields of an index_param secondary index information record.
 *
 * @param param  The index_param to be deallocated.
 */
void
free_index(index_param *param)
{
	cf_free(param->ns);
	cf_free(param->set);
	cf_free(param->name);

	for (uint32_t i = 0; i < param->path_vec.size; ++i) {
		path_param *param2 = as_vector_get(&param->path_vec, i);
		cf_free(param2->path);
	}

	as_vector_destroy(&param->path_vec);
}

/*
 * Deallocates a vector of index_param secondary index information records.
 *
 * @param index_vec  The vector of index_param records to be deallocated.
 */
void
free_indexes(as_vector *index_vec)
{
	ver("Freeing %u index(es)", index_vec->size);

	for (uint32_t i = 0; i < index_vec->size; ++i) {
		index_param *param = as_vector_get(index_vec, i);
		free_index(param);
	}
}

/*
 * Deallocates the fields of a user information record.
 *
 * @param param  The as_user to be deallocated.
 */
void
free_user(as_user *param)
{
	as_user_destroy(&param);
}

/*
 * Deallocates a vector of user information record.
 *
 * @param user_vec  The vector of as_user to be deallocated.
 * @param user_size The number of users to be deallocated
 */
void
free_users(as_vector *user_vec, int user_size)
{
	as_users_destroy(&user_vec, user_size);
}