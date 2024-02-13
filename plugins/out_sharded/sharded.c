#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <monkey/mk_core/mk_list.h>
#include <string.h>

struct out_sharded {
    struct mk_list shards;
    struct shard *current;
    char *prefix;
};

struct shard {
    struct flb_output_instance *output;
    struct mk_list _head;
};

static int cb_sharded_init(struct flb_output_instance *ins,
                         struct flb_config *config, void *data)
{
    struct out_sharded *ctx;
    int ret;
    flb_info("[out_shard]: initializing");

    ctx = flb_malloc(sizeof(struct out_sharded));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ret = flb_output_config_map_set(ins, (void*) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        flb_free(ctx);
        return -1;
    }
    mk_list_init(&ctx->shards);
    flb_output_set_context(ins, ctx);
    return 0;
}

static int cb_sharded_pre_run(void *data, struct flb_config *config)
{
    struct out_sharded *ctx = data;
    struct flb_output_instance *ins;
    struct shard *shard;
    struct mk_list *head;
    flb_info("[out_shard]: pre-run, prefix=%s", ctx->prefix);

    mk_list_foreach(head, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        if (strcmp(ins->name, "sharded") != 0 && ins->alias && strncmp(ins->alias, ctx->prefix, strlen(ctx->prefix)) == 0) {
            flb_info("[out_shard]: adding shard %s", ins->alias);
            shard = flb_malloc(sizeof(struct shard));
            if (!shard) {
                flb_errno();
                return -1;
            }
            shard->output = ins;
            mk_list_add(&shard->_head, &ctx->shards);
        }
    }
    ctx->current = mk_list_entry_first(&ctx->shards, struct shard, _head);
    return 0;
}

static int cb_sharded_exit(void *data, struct flb_config *config)
{
    struct out_sharded *ctx = data;
    struct mk_list *tmp;
    struct mk_list *head;
    struct shard *shard;

    mk_list_foreach_safe(head, tmp, &ctx->shards) {
        shard = mk_list_entry(head, struct shard, _head);
        mk_list_del(&shard->_head);
        flb_free(shard);
    }
    flb_free(ctx);
    return 0;
}

static struct flb_output_instance* cb_sharded_get_output(struct flb_output_instance *o_ins)
{
    struct out_sharded *ctx = o_ins->context;
    struct flb_output_instance *ins = ctx->current->output;

    ctx->current = mk_list_entry_next(&ctx->current->_head, struct shard, _head, &ctx->shards);
    if (!ctx->current) {
        ctx->current = mk_list_entry_first(&ctx->shards, struct shard, _head);
    }

    flb_warn("[out_sharded]: flushing to %s", ins->alias);
    return ins;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "prefix", "shard.",
        0, FLB_TRUE, offsetof(struct out_sharded, prefix),
        "Prefix for sharded output instances"
    },
    {0}
};

struct flb_output_plugin out_sharded_plugin = {
    .name        = "sharded",
    .description = "Sharded output plugin",
    .cb_init     = cb_sharded_init,
    .cb_pre_run  = cb_sharded_pre_run,
    .cb_get_output = cb_sharded_get_output,
    .cb_exit  = cb_sharded_exit,
    .config_map  = config_map,
    .flags       = FLB_OUTPUT_PLUGIN_INDIRECT,
};
