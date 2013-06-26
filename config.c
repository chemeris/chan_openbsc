#include <asterisk.h>
#include <asterisk/channel.h>
#include <asterisk/logger.h>
#include <asterisk/module.h>
#include <asterisk/utils.h>

#include "config.h"

#ifndef AST_MODULE
#define AST_MODULE "chan_openbsc"
#endif

struct conf_infos *conf_info; /* global settings */

static int parse_config_general(struct ast_config *cfg, struct conf_infos *conf_info)
{
	struct ast_variable *var = NULL;

	for (var = ast_variable_browse(cfg, "general"); var != NULL; var = var->next) {

		if (!strcasecmp(var->name, "hlr_db")) {
			ast_copy_string(conf_info->hlr_db_path, var->value, sizeof(conf_info->hlr_db_path));
			continue;

		} else if (!strcasecmp(var->name, "openbsc_cfg")) {
			ast_copy_string(conf_info->openbsc_cfg_path, var->value, sizeof(conf_info->openbsc_cfg_path));
			continue;

		} else if (!strcasecmp(var->name, "log")) {
			ast_copy_string(conf_info->log_path, var->value, sizeof(conf_info->log_path));

		} else if (!strcasecmp(var->name, "context")) {
			ast_copy_string(conf_info->context, var->value, sizeof(conf_info->context));
		}
	}

	return 0;
}

static int config_load(char *config_file, struct conf_infos *conf_info)
{
	struct ast_config *cfg = NULL;
	struct ast_flags config_flags = { 0 };

	ast_log(LOG_NOTICE, "Configuring openbsc from %s...\n", config_file);

	cfg = ast_config_load(config_file, config_flags);
	if (!cfg) {
		ast_log(LOG_ERROR, "Unable to load configuration file '%s'\n", config_file);
		return -1;
	}

	parse_config_general(cfg, conf_info);
	ast_config_destroy(cfg);

	return 0;
}

int config_init(struct conf_infos **conf_info)
{
	int ret = 0;

	*conf_info = ast_calloc(1, sizeof(struct conf_infos));
	if (*conf_info == NULL) {
		return -1;
	}

	ret = config_load("openbsc.conf", *conf_info);
	if (ret == -1) {
		ast_free(*conf_info);
		return -1;
	}

	ast_log(LOG_DEBUG, "log: %s\n", (*conf_info)->log_path);
	ast_log(LOG_DEBUG, "hlr_db: %s\n", (*conf_info)->hlr_db_path);
	ast_log(LOG_DEBUG, "openbsc_cfg: %s\n", (*conf_info)->openbsc_cfg_path);
	ast_log(LOG_DEBUG, "context: %s\n", (*conf_info)->context);

	return 0;
}
