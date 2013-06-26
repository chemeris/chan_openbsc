
#ifndef CONFIG_H
#define CONFIG_H

struct conf_infos {
	char log_path[1024];
	char hlr_db_path[1024];
	char openbsc_cfg_path[1024];
	char context[64];
};

int config_init(struct conf_infos **conf_info);

#endif

