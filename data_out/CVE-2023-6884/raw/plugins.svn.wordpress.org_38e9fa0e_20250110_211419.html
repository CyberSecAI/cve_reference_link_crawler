<?php

namespace WP_Rplg_Google_Reviews\Includes;

use WP_Rplg_Google_Reviews\Includes\Core\Core;

class Feed_Shortcode {

    private $core;
    private $view;
    private $assets;
    private $feed_old;
    private $feed_deserializer;

    public function __construct(Feed_Deserializer $feed_deserializer, Assets $assets, Core $core, View $view, Feed_Old $feed_old) {
        $this->feed_deserializer = $feed_deserializer;
        $this->assets            = $assets;
        $this->core              = $core;
        $this->view              = $view;
        $this->feed_old          = $feed_old;
    }

    public function register() {
        add_shortcode('grw', array($this, 'init'));
    }

    public function init($atts) {
        if (get_option('grw_active') === '0') {
            return '';
        }

        if (isset($atts['place_id']) && strlen($atts['place_id']) > 0) {
            $feed = $this->feed_old->get_feed($atts['place_id'], $atts);

        } else {
            $atts = shortcode_atts(array('id' => 0), $atts, 'grw');
            $feed = $this->feed_deserializer->get_feed($atts['id']);

            if (!$feed) {
                return null;
            }
        }

        $grw_demand_assets = get_option('grw_demand_assets');
        if ($grw_demand_assets || $grw_demand_assets == 'true') {
            $this->assets->enqueue_public_styles();
            $this->assets->enqueue_public_scripts();
        }

        $data = $this->core->get_reviews($feed);
        return $this->view->render($feed->ID, $data['businesses'], $data['reviews'], $data['options']);
    }
}
